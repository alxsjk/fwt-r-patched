"""Client datatable rebalance for Alex (Feature 12.02: --alex-rebalance).

Rebalances Alex's active skills 1-3 and passive (Knighthood) across all 8
localized ``skilldata*.unity3d`` and ``skilleffecttable*.unity3d`` bundles, and
adds Thornbush (``MovingType.Thornbush = 5``) as Alex's second terrain
advantage (``_moveType1 = 5`` alongside ``_moveType0 = 1`` Field) across all 8
``creaturedata*.unity3d`` bundles inside ``assets/fwt_resources_v1.zip``. When
combined with Feature 12.01 (``--alex-awakening``), also updates Destiny Lance
(``0x100185``) to trigger a permanent 1-cell Thornbush conversion centered on
the Boss's destination cell (while keeping single-target boss swap geometry in
the skill row).
"""

from __future__ import annotations

import copy
import re
import struct
import zipfile
from collections.abc import Callable
from typing import Any

ALEX_SKILL_1_ID = 1048961
ALEX_SKILL_2_ID = 1048962
ALEX_SKILL_3_ID = 1048964
ALEX_PASSIVE_ID = 1048963
ALEX_AWAKE_SKILL_ID = 0x100185

ALEX_SKILL_1_MOVE_ATK_EFFECT = 24514561
ALEX_OLD_DEBUFF_BONUS_EFFECT = 23531569
ALEX_SKILL_1_DAMAGE_EFFECT = 16846913

ALEX_SKILL_2_FIXED_ATK_DOWN_EFFECT = 18419715
ALEX_SKILL_2_DOT_EFFECT = 17174567
ALEX_SKILL_2_DAMAGE_EFFECT = 16846914

ALEX_SKILL_3_STUN_EFFECT = 17371140
ALEX_SKILL_3_DAMAGE_EFFECT = 16846915

ALEX_PASSIVE_CRIT_DMG_DOWN_EFFECT = 26742786
IAN_COOP_EFFECT_ID = 23531665

# Donor IDs present across all 8 localized skilleffecttable*.unity3d bundles
DONOR_ATK_RATE_DOWN_EFFECT = 23072800
DONOR_DR_DOWN_RATE_EFFECT = 36835330  # DRDownRate (type 132), vt=2, precon 255, icon D_SkillIcon_33
DONOR_COOP_UTILITY_EFFECT = 23531665
DONOR_PASSIVE_FINAL_POWER_BUFF = 23662625
DONOR_PASSIVE_ALL_DMG_REDUCE = 37818374
DONOR_TILE_CHANGE_THORNBUSH = 39915523
ALEX_AWAKE_DAMAGE_EFFECT_ID = 0x10018501
DONOR_SWAP_EFFECT_ID = 21172225

# Collision-free effect IDs for Alex rebalance (0x100181xx)
# 0x10018101 (AtkDownRate) was retired in 2.5.54 — replaced by 0x10018107 (DRDownRate).
NEW_DR_DOWN_RATE_EFFECT_ID = 0x10018107
NEW_COOP_UTILITY_10_25_ID = 0x10018102
NEW_PASSIVE_COOP_20_ID = 0x10018103
NEW_PASSIVE_ALLY_DR_5_25_ID = 0x10018104
NEW_PASSIVE_DEBUFF_10_ID = 0x10018105
NEW_AWAKE_THORNBUSH_ID = 0x10018106

BASE_EFFECT_IDS = (
    NEW_DR_DOWN_RATE_EFFECT_ID,
    NEW_COOP_UTILITY_10_25_ID,
    NEW_PASSIVE_COOP_20_ID,
    NEW_PASSIVE_ALLY_DR_5_25_ID,
    NEW_PASSIVE_DEBUFF_10_ID,
)
AWAKE_EFFECT_IDS = (NEW_AWAKE_THORNBUSH_ID,)

_STEPS_TO_MAX = 9.0

AWAKE_THORNBUSH_TOOLTIP = (
    "Deals [FF0000]{0}%[FFFFFF] of Attack as damage to a Boss, exchanges positions with it, "
    "and permanently turns tiles within 1 cell around the Boss into [41FF3A]Thornbush[FFFFFF]. "
    "Choose a Boss if more than one is present.@1-3"
)

ENGLISH_TOOLTIPS: dict[int, str] = {
    ALEX_SKILL_1_ID: (
        "Attacks enemies within range and inflicts damage at [FF0000]{0}%[FFFFFF] of Attack. "
        "Instantly increases Attack by [41FF3A]{2}%[FFFFFF] for every space traveled for {1} turn(s). "
        "Cooperative attacks increase this skill's Final Power by [41FF3A]{3}%[FFFFFF]."
        "@3-3@0-1@1-3@2-3"
    ),
    ALEX_SKILL_2_ID: (
        "Attacks enemies within range and inflicts damage at [FF0000]{0}%[FFFFFF] of Attack. "
        "Decreases the enemies' Defense by [FF0000]{3}%[FFFFFF] for {2} turn(s) with a [00D4FF]{1}%[FFFFFF] chance, "
        "and inflicts [FF0000]{4}%[FFFFFF] damage over time. "
        "Cooperative attacks increase this skill's Final Power by [41FF3A]{5}%[FFFFFF]."
        "@4-3@0-0@0-1@1-3@2-3@3-3"
    ),
    ALEX_SKILL_3_ID: (
        "Pounces on enemies within range, inflicting [FF0000]{0}%[FFFFFF] damage of Attack "
        "and [FF0000]Stunning[FFFFFF] them for {2} turn(s) with a [00D4FF]{1}%[FFFFFF] chance. "
        "Cooperative attacks increase this skill's Final Power by [41FF3A]{3}%[FFFFFF]."
        "@3-3@0-0@0-1@2-3"
    ),
    ALEX_PASSIVE_ID: (
        "Alex inflicts additional damage of [41FF3A]{0}%[FFFFFF] on enemies that are under debuff effect(s). "
        "Deals [41FF3A]{1}%[FFFFFF] additional damage in cooperative attacks. "
        "While at least [00D4FF]{2}[FFFFFF] allies are alive, reduces incoming damage by [41FF3A]{3}%[FFFFFF]."
        "@1-3@2-3@3-2@3-3"
    ),
    ALEX_AWAKE_SKILL_ID: AWAKE_THORNBUSH_TOOLTIP,
}

SKILLDATA_PATH_RE = re.compile(r"files/Resources/datatable/skilldata[a-z]*\.unity3d")
EFFECTTABLE_PATH_RE = re.compile(r"files/Resources/datatable/skilleffecttable[a-z]*\.unity3d")
CREATUREDATA_PATH_RE = re.compile(r"files/Resources/datatable/creaturedata[a-z]*\.unity3d")

ALEX_CREATURE_IDS: tuple[int, ...] = (
    1245569,
    1245570,
    1245571,
    1245572,
    1245573,
    1245574,
    3342725,
)
ALEX_MOVETYPE_FIELD = 1
ALEX_MOVETYPE_THORNBUSH = 5
ALEX_MOVETYPE_NONE = 255


def _f32(value: float) -> float:
    """Round a Python float to IEEE-754 float32 precision used by Unity MonoBehaviour."""
    return float(struct.unpack("<f", struct.pack("<f", value))[0])


def _update_tooltip(path: str, sid: int, current_tooltip: str) -> str:
    if sid == ALEX_AWAKE_SKILL_ID:
        return AWAKE_THORNBUSH_TOOLTIP
    if path.endswith("/skilldataenglish.unity3d"):
        return ENGLISH_TOOLTIPS[sid]
    if current_tooltip == "-1":
        return "-1"
    if sid == ALEX_SKILL_1_ID and path.endswith("/skilldatajapanese.unity3d"):
        return current_tooltip.replace("@2-3", "@3-3")
    if sid == ALEX_SKILL_2_ID and path.endswith("/skilldatajapanese.unity3d"):
        return current_tooltip.replace("@3-3", "@4-3")
    if sid == ALEX_SKILL_3_ID and path.endswith("/skilldatajapanese.unity3d"):
        return current_tooltip.replace("@2-3", "@3-3")
    return current_tooltip


def expected_skill_updates(path: str, sid: int, current_tooltip: str) -> dict[str, Any]:
    """Return expected field overrides for a rebalanced Alex skill row."""
    if sid not in ENGLISH_TOOLTIPS:
        raise ValueError(f"Unsupported skill ID: {sid}")
    tooltip = _update_tooltip(path, sid, current_tooltip)
    if sid == ALEX_SKILL_1_ID:
        return {
            # Cast range and AoE pattern now match Skill 2 (Sehee-derived (5, 13, 5, 19)).
            "_range": 5,
            "_skillRangeType": 13,
            "_skillEffectRange": 5,
            "_skillEffectRangeType": 19,
            "_effect01": ALEX_SKILL_1_MOVE_ATK_EFFECT,
            "_effect02": IAN_COOP_EFFECT_ID,
            "_effect03": ALEX_SKILL_1_DAMAGE_EFFECT,
            "_effect04": -1,
            "_tooltip": tooltip,
        }
    if sid == ALEX_SKILL_2_ID:
        return {
            "_range": 5,
            "_skillRangeType": 13,
            "_skillEffectRange": 5,
            "_skillEffectRangeType": 19,
            "_effect01": NEW_DR_DOWN_RATE_EFFECT_ID,
            "_effect02": ALEX_SKILL_2_DOT_EFFECT,
            "_effect03": NEW_COOP_UTILITY_10_25_ID,
            "_effect04": ALEX_SKILL_2_DAMAGE_EFFECT,
            "_tooltip": tooltip,
        }
    if sid == ALEX_SKILL_3_ID:
        return {
            # Cast range from Jakyak's Do not Chase me (1056868).
            "_range": 3,
            "_skillRangeType": 13,
            "_skillEffectRange": 3,
            "_skillEffectRangeType": 8,
            "_effect01": ALEX_SKILL_3_STUN_EFFECT,
            "_effect02": NEW_COOP_UTILITY_10_25_ID,
            "_effect03": ALEX_SKILL_3_DAMAGE_EFFECT,
            "_effect04": -1,
            "_tooltip": tooltip,
        }
    if sid == ALEX_PASSIVE_ID:
        return {
            "_effect01": NEW_PASSIVE_DEBUFF_10_ID,
            "_effect02": NEW_PASSIVE_COOP_20_ID,
            "_effect03": NEW_PASSIVE_ALLY_DR_5_25_ID,
            "_effect04": -1,
            "_tooltip": tooltip,
        }
    if sid == ALEX_AWAKE_SKILL_ID:
        return {
            "_skillEffectRange": 0,
            "_skillEffectRangeType": 0,
            "_turnStart": 0,
            "_turnEnd": 99,
            "_effect01": ALEX_AWAKE_DAMAGE_EFFECT_ID,
            "_effect02": DONOR_SWAP_EFFECT_ID,
            "_effect03": NEW_AWAKE_THORNBUSH_ID,
            "_effect04": -1,
            "_tooltip": AWAKE_THORNBUSH_TOOLTIP,
        }
    raise ValueError(f"Unsupported skill ID: {sid}")


def build_rebalance_effect_rows(
    by_id: dict[int, dict[str, Any]],
    *,
    include_awake: bool,
) -> list[dict[str, Any]]:
    """Build the new collision-free skilleffecttable rows for Alex rebalance."""
    dr_down = copy.deepcopy(by_id[DONOR_DR_DOWN_RATE_EFFECT])
    dr_down.update(
        _skillEffectId=NEW_DR_DOWN_RATE_EFFECT_ID,
        _effectValue=_f32(-0.10),
        _effectValueFactor=_f32(-0.20 / _STEPS_TO_MAX),
    )

    coop_10_25 = copy.deepcopy(by_id[DONOR_COOP_UTILITY_EFFECT])
    coop_10_25.update(
        _skillEffectId=NEW_COOP_UTILITY_10_25_ID,
        _precondition=78,
        _preconValue=_f32(1.0),
        _preconValue2=-1,
        _effectValue=_f32(0.10),
        _effectValueFactor=_f32(0.15 / _STEPS_TO_MAX),
    )

    passive_coop_20 = copy.deepcopy(by_id[DONOR_PASSIVE_FINAL_POWER_BUFF])
    passive_coop_20.update(
        _skillEffectId=NEW_PASSIVE_COOP_20_ID,
        _effectTarget=0,
        _precondition=78,
        _preconValue=_f32(1.0),
        _preconValue2=-1,
        _effectValue=_f32(0.20),
        _effectValueFactor=_f32(0.0),
    )

    passive_ally_dr = copy.deepcopy(by_id[DONOR_PASSIVE_ALL_DMG_REDUCE])
    passive_ally_dr.update(
        _skillEffectId=NEW_PASSIVE_ALLY_DR_5_25_ID,
        _effectTarget=0,
        _precondition=72,
        _preconValue=_f32(2.0),
        _preconValue2=-1,
        _effectValue=_f32(-0.05),
        _effectValueFactor=_f32(-0.20 / _STEPS_TO_MAX),
    )

    passive_debuff_10 = copy.deepcopy(by_id[DONOR_PASSIVE_FINAL_POWER_BUFF])
    passive_debuff_10.update(
        _skillEffectId=NEW_PASSIVE_DEBUFF_10_ID,
        _effectTarget=0,
        _precondition=39,
        _preconValue=_f32(1.0),
        _preconValue2=-1,
        _effectValue=_f32(0.10),
        _effectValueFactor=_f32(0.0),
    )

    rows = [dr_down, coop_10_25, passive_coop_20, passive_ally_dr, passive_debuff_10]
    if not include_awake:
        return rows

    awake_thornbush = copy.deepcopy(by_id[DONOR_TILE_CHANGE_THORNBUSH])
    awake_thornbush.update(
        _skillEffectId=NEW_AWAKE_THORNBUSH_ID,
        _effectValue=_f32(5.0),
        _effectValueFactor=_f32(0.0),
    )

    rows.append(awake_thornbush)
    return rows


def _save_and_verify_bundle(
    path: str,
    raw_bundle: bytes,
    mutate_fn: Callable[[list[dict[str, Any]]], tuple[bool, list[dict[str, Any]]]],
) -> bytes | None:
    import UnityPy

    from core.apk_tooling import _decrypt_datatable, _encrypt_datatable

    clear, key, iv = _decrypt_datatable(raw_bundle)
    env = UnityPy.load(clear)
    objects = [obj for obj in env.objects if obj.type.name == "MonoBehaviour"]
    if len(objects) != 1:
        raise ValueError(f"Unexpected MonoBehaviour count in {path}: {len(objects)}")
    obj = objects[0]
    tree = obj.read_typetree()
    rows: list[dict[str, Any]] = tree.get("_data") or []
    changed, expected = mutate_fn(rows)
    if not changed:
        return None
    tree["_data"] = expected
    obj.save_typetree(tree)

    encoded = _encrypt_datatable(
        bytes(getattr(env.file, "save")(packer="original")),  # noqa: B009
        key,
        iv,
    )
    reloaded, _, _ = _decrypt_datatable(encoded)
    reloaded_objs = [o for o in UnityPy.load(reloaded).objects if o.type.name == "MonoBehaviour"]
    if len(reloaded_objs) != 1:
        raise ValueError(f"Unexpected reloaded object count in {path}")
    decoded: list[dict[str, Any]] = reloaded_objs[0].read_typetree().get("_data") or []
    if decoded != expected:
        raise ValueError(f"Round-trip mismatch in {path}")
    return encoded


def _patch_effecttable_bundle(
    path: str,
    raw_bundle: bytes,
    *,
    include_awake: bool,
) -> bytes | None:
    required_donors: tuple[int, ...] = (
        DONOR_DR_DOWN_RATE_EFFECT,
        DONOR_COOP_UTILITY_EFFECT,
        DONOR_PASSIVE_FINAL_POWER_BUFF,
        DONOR_PASSIVE_ALL_DMG_REDUCE,
        *((DONOR_TILE_CHANGE_THORNBUSH,) if include_awake else ()),
    )

    def mutate(rows: list[dict[str, Any]]) -> tuple[bool, list[dict[str, Any]]]:
        by_id: dict[int, dict[str, Any]] = {
            int(row["_skillEffectId"]): row for row in rows if "_skillEffectId" in row
        }
        for donor in required_donors:
            if donor not in by_id:
                raise ValueError(f"Donor effect {donor} missing from {path}")
        new_rows = build_rebalance_effect_rows(by_id, include_awake=include_awake)
        if all(by_id.get(int(row["_skillEffectId"])) == row for row in new_rows):
            return False, rows
        for row in new_rows:
            cid = int(row["_skillEffectId"])
            if cid in by_id:
                raise ValueError(f"Candidate effect ID {cid:#x} already exists in {path}")
        return True, [*copy.deepcopy(rows), *new_rows]

    return _save_and_verify_bundle(path, raw_bundle, mutate)


def _patch_skilldata_bundle(path: str, raw_bundle: bytes) -> bytes | None:
    from core.alex_awakening_assets import _DAMAGE as AWAKE_STOCK_DAMAGE
    from core.alex_awakening_assets import _SWAP as AWAKE_STOCK_SWAP

    target_baselines: dict[int, tuple[int, int, int, int]] = {
        ALEX_SKILL_1_ID: (
            ALEX_SKILL_1_MOVE_ATK_EFFECT,
            ALEX_OLD_DEBUFF_BONUS_EFFECT,
            ALEX_SKILL_1_DAMAGE_EFFECT,
            -1,
        ),
        ALEX_SKILL_2_ID: (
            ALEX_SKILL_2_FIXED_ATK_DOWN_EFFECT,
            ALEX_SKILL_2_DOT_EFFECT,
            ALEX_OLD_DEBUFF_BONUS_EFFECT,
            ALEX_SKILL_2_DAMAGE_EFFECT,
        ),
        ALEX_SKILL_3_ID: (
            ALEX_SKILL_3_STUN_EFFECT,
            ALEX_OLD_DEBUFF_BONUS_EFFECT,
            ALEX_SKILL_3_DAMAGE_EFFECT,
            -1,
        ),
        ALEX_PASSIVE_ID: (
            ALEX_PASSIVE_CRIT_DMG_DOWN_EFFECT,
            -1,
            -1,
            -1,
        ),
    }

    def mutate(rows: list[dict[str, Any]]) -> tuple[bool, list[dict[str, Any]]]:
        updated = copy.deepcopy(rows)
        seen: set[int] = set()
        changed = False
        for row in updated:
            sid = row.get("_skillId")
            if sid in target_baselines:
                if sid in seen:
                    raise ValueError(f"Duplicate skill {sid} in {path}")
                seen.add(sid)
                expected_updates = expected_skill_updates(path, sid, str(row.get("_tooltip", "-1")))
                if all(row.get(k) == v for k, v in expected_updates.items()):
                    continue
                actual = (
                    row.get("_effect01"),
                    row.get("_effect02"),
                    row.get("_effect03"),
                    row.get("_effect04"),
                )
                if actual != target_baselines[sid]:
                    raise ValueError(f"Unexpected baseline effects on {sid} in {path}: {actual}")
                row.update(expected_updates)
                changed = True
            elif sid == ALEX_AWAKE_SKILL_ID:
                if sid in seen:
                    raise ValueError(f"Duplicate skill {sid} in {path}")
                seen.add(sid)
                expected_updates = expected_skill_updates(path, sid, str(row.get("_tooltip", "-1")))
                if all(row.get(k) == v for k, v in expected_updates.items()):
                    continue
                if row.get("_effect01") != AWAKE_STOCK_DAMAGE or row.get("_effect02") != AWAKE_STOCK_SWAP:
                    raise ValueError(f"Unexpected baseline effects on Awake {sid} in {path}")
                row.update(expected_updates)
                changed = True
        if not set(target_baselines).issubset(seen):
            raise ValueError(f"Missing target skills in {path}: {set(target_baselines) - seen}")
        return changed, updated

    return _save_and_verify_bundle(path, raw_bundle, mutate)


def _patch_creaturedata_bundle(path: str, raw_bundle: bytes) -> bytes | None:
    target_ids = set(ALEX_CREATURE_IDS)

    def mutate(rows: list[dict[str, Any]]) -> tuple[bool, list[dict[str, Any]]]:
        updated = copy.deepcopy(rows)
        seen: set[int] = set()
        changed = False
        for row in updated:
            cid = row.get("_creatureId")
            if cid not in target_ids:
                continue
            if cid in seen:
                raise ValueError(f"Duplicate creature {cid} in {path}")
            seen.add(cid)
            if (
                row.get("_moveType0") == ALEX_MOVETYPE_FIELD
                and row.get("_moveType1") == ALEX_MOVETYPE_THORNBUSH
            ):
                continue
            if (
                row.get("_moveType0") != ALEX_MOVETYPE_FIELD
                or row.get("_moveType1") != ALEX_MOVETYPE_NONE
            ):
                raise ValueError(
                    f"Unexpected moveTypes on Alex creature {cid} in {path}: "
                    f"({row.get('_moveType0')}, {row.get('_moveType1')})"
                )
            row["_moveType1"] = ALEX_MOVETYPE_THORNBUSH
            changed = True
        if seen != target_ids:
            raise ValueError(f"Missing Alex creatures in {path}: {sorted(target_ids - seen)}")
        return changed, updated

    return _save_and_verify_bundle(path, raw_bundle, mutate)


def _read_rows(raw_bundle: bytes) -> list[dict[str, Any]]:
    import UnityPy

    from core.apk_tooling import _decrypt_datatable

    clear, _, _ = _decrypt_datatable(raw_bundle)
    objs = [o for o in UnityPy.load(clear).objects if o.type.name == "MonoBehaviour"]
    if len(objs) != 1:
        raise ValueError(f"Unexpected MonoBehaviour count: {len(objs)}")
    return list(objs[0].read_typetree().get("_data") or [])


def prepare_alex_rebalance_assets(
    archive: zipfile.ZipFile,
    *,
    existing_replacements: dict[str, bytes] | None = None,
) -> dict[str, bytes]:
    """Patch all 8 skilldata, 8 skilleffecttable, and 8 creaturedata bundles."""
    skill_paths = sorted(p for p in archive.namelist() if SKILLDATA_PATH_RE.fullmatch(p))
    effect_paths = sorted(p for p in archive.namelist() if EFFECTTABLE_PATH_RE.fullmatch(p))
    creature_paths = sorted(p for p in archive.namelist() if CREATUREDATA_PATH_RE.fullmatch(p))
    if len(skill_paths) != 8:
        raise ValueError(f"Expected 8 localized skilldata tables, found {len(skill_paths)}")
    if len(effect_paths) != 8:
        raise ValueError(f"Expected 8 localized skilleffecttable tables, found {len(effect_paths)}")
    if len(creature_paths) != 8:
        raise ValueError(f"Expected 8 localized creaturedata tables, found {len(creature_paths)}")

    def read_bundle(path: str) -> bytes:
        if existing_replacements and path in existing_replacements:
            return existing_replacements[path]
        return archive.read(path)

    # Include Awake Thornbush effects when Destiny Lance (0x100185) is present.
    probe_skills = _read_rows(read_bundle(skill_paths[0]))
    include_awake = any(row.get("_skillId") == ALEX_AWAKE_SKILL_ID for row in probe_skills)

    result: dict[str, bytes] = {}
    for path in effect_paths:
        patched = _patch_effecttable_bundle(path, read_bundle(path), include_awake=include_awake)
        if patched is not None:
            result[path] = patched
    for path in skill_paths:
        patched = _patch_skilldata_bundle(path, read_bundle(path))
        if patched is not None:
            result[path] = patched
    for path in creature_paths:
        patched = _patch_creaturedata_bundle(path, read_bundle(path))
        if patched is not None:
            result[path] = patched
    return result


def inspect_alex_rebalance_assets(archive: zipfile.ZipFile) -> tuple[bool, str]:
    """Independently verify all 8 skilldata, 8 skilleffecttable, and 8 creaturedata bundles."""
    try:
        import cryptography  # noqa: F401
        import UnityPy  # noqa: F401
    except ImportError:
        return False, "Optional dependencies (UnityPy/cryptography) not available"

    skill_paths = sorted(p for p in archive.namelist() if SKILLDATA_PATH_RE.fullmatch(p))
    effect_paths = sorted(p for p in archive.namelist() if EFFECTTABLE_PATH_RE.fullmatch(p))
    creature_paths = sorted(p for p in archive.namelist() if CREATUREDATA_PATH_RE.fullmatch(p))
    if len(skill_paths) != 8 or len(effect_paths) != 8 or len(creature_paths) != 8:
        return False, "Missing localized skilldata, skilleffecttable, or creaturedata bundles"

    awake_present: bool | None = None
    for path in skill_paths:
        rows = _read_rows(archive.read(path))
        by_id = {row.get("_skillId"): row for row in rows}
        has_awake = ALEX_AWAKE_SKILL_ID in by_id
        if awake_present is None:
            awake_present = has_awake
        elif awake_present != has_awake:
            return False, f"Inconsistent Destiny Lance presence in {path}"
        targets = (
            ALEX_SKILL_1_ID,
            ALEX_SKILL_2_ID,
            ALEX_SKILL_3_ID,
            ALEX_PASSIVE_ID,
            *((ALEX_AWAKE_SKILL_ID,) if has_awake else ()),
        )
        for sid in targets:
            row = by_id.get(sid)
            if row is None:
                return False, f"Skill {sid} missing in {path}"
            expected = expected_skill_updates(path, sid, str(row.get("_tooltip", "-1")))
            for key, value in expected.items():
                if row.get(key) != value:
                    return False, f"Skill {sid} field {key} not rebalanced in {path}"

    include_awake = bool(awake_present)
    for path in effect_paths:
        rows = _read_rows(archive.read(path))
        effect_by_id = {
            int(row["_skillEffectId"]): row for row in rows if "_skillEffectId" in row
        }
        try:
            expected_rows = build_rebalance_effect_rows(effect_by_id, include_awake=include_awake)
        except KeyError as exc:
            return False, f"Donor effect {exc} missing in {path}"
        for exp_row in expected_rows:
            eid = int(exp_row["_skillEffectId"])
            if effect_by_id.get(eid) != exp_row:
                return False, f"Effect {eid:#x} missing or mismatched in {path}"

    for path in creature_paths:
        rows = _read_rows(archive.read(path))
        by_cid = {row.get("_creatureId"): row for row in rows if "_creatureId" in row}
        for cid in ALEX_CREATURE_IDS:
            row = by_cid.get(cid)
            if row is None:
                return False, f"Alex creature {cid} missing in {path}"
            if (
                row.get("_moveType0") != ALEX_MOVETYPE_FIELD
                or row.get("_moveType1") != ALEX_MOVETYPE_THORNBUSH
            ):
                return False, f"Alex creature {cid} missing Thornbush terrain advantage in {path}"

    if include_awake:
        return True, (
            "Skills 1-3, Passive, Thornbush terrain advantage, and Destiny Lance "
            "1-cell Thornbush verified across 24 tables"
        )
    return True, "Skills 1-3, Passive, and Thornbush terrain advantage verified across 24 tables"
