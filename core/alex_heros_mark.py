"""Alex's Hero's Mark "The Unbroken Lance" (Feature 12.03: --alex-heros-mark).

Creates a Hero's Mark for Alex (creatureId 0x130181) in his Soul Gear tab:
- Mark row (partsType=3) in ``soulgeartable*.unity3d`` (8 locales) reusing
  Thanatos's artwork (``UI_Icon_Markofhero_BlackDragon_01``)
- Per-level skill boost in ``skilloverlaptable*.unity3d`` (8 locales, group 20490):
  Destiny Lance gains +25% damage per mark level on ``_effect01`` (cumulative
  +250% at Lv10)
- Set effects in ``setitemtable*.unity3d`` (8 locales): team-wide +20%
  Final Skill Power (type 68 FinalDamageUpByRateBuff) and +10% Attack while >=1 ally
  is alive (type 58 APUpRate, precon 72)
- Server ``fwt_valid_soulgear_idx`` (``kIds``) cave in ``libfwt_local_server.so``
  so Alex's mark ID (``0x13018110``) passes make/grant/assign/parts validation
- Client runtime hook on ``Skill::GetCurrentCoolTime`` (``0x16064b4``) so
  Destiny Lance's cooldown drops from 1 to 0 only when Alex's Hero's Mark
  is equipped and enchanted to level 10

The mark's Destiny Lance boost composes with 12.01 (--alex-awakening);
the set effects work regardless.
"""
from __future__ import annotations

import math
import struct
import zipfile
from pathlib import Path
from typing import Any


def _f32(value: float) -> float:
    """Round a Python float to IEEE-754 float32 precision."""
    return float(struct.unpack("<f", struct.pack("<f", value))[0])


# --- Mark row constants (soulgeartable) ---
ALEX_CREATURE_ID = 0x130181
ALEX_MARK_SOULGEAR_ID = 318865680  # weapon 318865665 + 15 (Thanatos pattern)
ALEX_MARK_NAME = "The Unbroken Lance"
ALEX_MARK_PARTS_TYPE = 3
ALEX_MARK_NUMBER = 10
ALEX_MARK_CHOICE_TYPE = 8  # Lily-pattern (two-effect set structure)
ALEX_MARK_SKILL_GROUP_ID = 20490  # first free overlap group
ALEX_MARK_SET_GROUP_ID = 30051  # first free set group (30048 is the stock "Vampire" set)
ALEX_MARK_ICON = "UI_Icon_Markofhero_BlackDragon_01"
ALEX_MARK_ICON_FOLDER = "Soulgear_Theme_100"
ALEX_MARK_STATS = {"_attack": 380, "_cr": _f32(0.02), "_hp": -1, "_mp": -1, "_mpRegen": _f32(-1.0),
                   "_movePoint": 255, "_dr": _f32(-1.0), "_dgr": _f32(-1.0), "_hr": _f32(-1.0),
                   "_car": _f32(-1.0), "_cadr": _f32(-1.0), "_mastery": _f32(-1.0), "_cp": 255}

SOULGEAR_PATH_RE = "files/Resources/datatable/soulgeartable"
SETITEM_PATH_RE = "files/Resources/datatable/setitemtable"
OVERLAP_PATH = "files/Resources/datatable/skilloverlaptable.unity3d"
SKILLDATA_PATH_RE = "files/Resources/datatable/skilldata"
EFFECTTABLE_PATH_RE = "files/Resources/datatable/skilleffecttable"

# --- Overlap group (per-level Destiny Lance boost) ---
DESTINY_LANCE_SKILL_ID = 0x100185
DESTINY_LANCE_COOLTIME_STOCK = 1  # from skilldata: _cooltime = 1
OVERLAP_LEVELS = tuple(range(1, 11))  # equipLevel 1..10 (no level 0 in native marks)
OVERLAP_BOOST_PER_LEVEL = 0.25  # +25% per mark level, cumulative
OVERLAP_BOOST_TYPE = 1  # _effect01ExtravalueType = 1 (damage increase on Destiny Lance _effect01)


def overlap_description(level: int) -> str:
    """Per-level text shown in the mark's upgrade list.

    Written as literal text (the stock marked sets also do this, e.g. group
    4146) so the number is visible even if the ``{0}@1-2`` placeholder renderer
    is not applied on this screen. The percentage comes from the same constant
    that feeds ``_effect01Extravalue``, so text and effect cannot diverge.
    """
    percent = int(round(OVERLAP_BOOST_PER_LEVEL * level * 100))
    text = f"Increases Destiny Lance damage by [FF0000]{percent}%[FFFFFF]."
    if level == max(OVERLAP_LEVELS):
        text += " Decreases Awakening Skill Cooldown by 1."
    return text

# --- Set skill (passive with two effects) ---
ALEX_SET_SKILL_ID = 11557000  # collision-free (Lily uses 11556949)
ALEX_SET_SKILL_NAME = "The Unbroken Lance"
ALEX_SET_EFFECT01_ID = 0x10018301  # collision-free skilleffecttable row
ALEX_SET_EFFECT02_ID = 0x10018302  # collision-free skilleffecttable row

# Effect 1: team-wide +20% Final Skill Power (type 68, FinalDamageUpByRateBuff)
DONOR_FINAL_POWER_BUFF = 23667812  # Lily's effect01 donor (type 68)
# Effect 2: +10% Attack with >=1 ally (type 58, APUpRate)
DONOR_AP_UP_RATE = 22614017  # type 58 donor

# --- Set item row (setitemtable) ---
SET_ITEM_GRADE = 99
SET_COMBATPOWER = 0.0135
SET_CPTYPE = 1


def _is_close(a: Any, b: float, tol: float = 1e-6) -> bool:
    try:
        return math.isclose(float(a), b, rel_tol=0.0, abs_tol=tol)
    except (ValueError, TypeError):
        return False


def _has_valid_mark_effects(rows: list[dict[str, Any]]) -> bool:
    """Check the currently implemented set effects, including their semantics."""
    expected = (
        (ALEX_SET_EFFECT01_ID, 68, 2, 255, -1.0, 0.20),
        (ALEX_SET_EFFECT02_ID, 58, 2, 72, 1.0, 0.10),
    )
    for effect_id, effect_type, target, condition, condition_value, value in expected:
        matches = [r for r in rows if int(r.get("_skillEffectId", -1)) == effect_id]
        if len(matches) != 1:
            return False
        row = matches[0]
        if not (
            int(row.get("_skillEffectType", -1)) == effect_type
            and int(row.get("_effectTarget", -1)) == target
            and int(row.get("_precondition", -1)) == condition
            and _is_close(row.get("_preconValue"), condition_value)
            and _is_close(row.get("_effectValue"), value)
            and _is_close(row.get("_effectValueFactor"), 0.0)
            and int(row.get("_effectValueType", -1)) == 2
        ):
            return False
    return True


def build_mark_row(locale_name: str) -> dict[str, Any]:
    """Build the soulgeartable row for Alex's Hero's Mark."""
    row: dict[str, Any] = {
        "_soulgearId": ALEX_MARK_SOULGEAR_ID,
        "_creatureId": ALEX_CREATURE_ID,
        "_number": ALEX_MARK_NUMBER,
        "_partsType": ALEX_MARK_PARTS_TYPE,
        "_choiceType": ALEX_MARK_CHOICE_TYPE,
        "_name": locale_name,
        "_skillGroupId": ALEX_MARK_SKILL_GROUP_ID,
        "_setgroupid": ALEX_MARK_SET_GROUP_ID,
        "_maxEncahnt": 10,
        "_maxUpgradeGear": 5,
        "_prefeb": "-1",
        "_iconFolder": ALEX_MARK_ICON_FOLDER,
        "_icon": ALEX_MARK_ICON,
    }
    row.update(ALEX_MARK_STATS)
    return row


def build_overlap_rows() -> list[dict[str, Any]]:
    """Build the skilloverlaptable rows for Alex's mark (group 20490, levels 1..10)."""
    rows: list[dict[str, Any]] = []
    for level in OVERLAP_LEVELS:
        boost = _f32(OVERLAP_BOOST_PER_LEVEL * level)
        rows.append({
            "_groupId": ALEX_MARK_SKILL_GROUP_ID,
            "_equipLevel": level,
            "_skillId": DESTINY_LANCE_SKILL_ID,
            "_range": 0,
            "_effectRange": 0,
            "_effectChance": 0.0,
            "_turnEnd": 0,
            "_useParameter": 0,
            "_effect01ExtravalueType": OVERLAP_BOOST_TYPE,
            "_effect01Extravalue": boost,
            "_effect01ExtraSkilleffectId": -1,
            "_effect02ExtravalueType": 255,
            "_effect02Extravalue": 0.0,
            "_effect02ExtraSkilleffectId": -1,
            "_effect03ExtravalueType": 255,
            "_effect03Extravalue": 0.0,
            "_effect03ExtraSkilleffectId": -1,
            "_effect04ExtravalueType": 255,
            "_effect04Extravalue": 0.0,
            "_effect04ExtraSkilleffectId": -1,
            "_desEquip": overlap_description(level),
            "_desSwitch": 255,
            "_desSkilldata": "-1",
        })
    return rows


def build_set_row(locale_name: str) -> dict[str, Any]:
    """Build the setitemtable row for Alex's mark set effects."""
    return {
        "_setgroupid": ALEX_MARK_SET_GROUP_ID,
        "_equipType": ALEX_MARK_PARTS_TYPE,
        "_setitemNum": 1,
        "_setName": locale_name,
        "_itemGrade": SET_ITEM_GRADE,
        "_setSkillid01": ALEX_SET_SKILL_ID,
        "_setSkillid02": -1,
        "_setSkillid03": -1,
        "_setSkillid04": -1,
        "_setPreconditionText": "-1",
        "_setPreconditionid": -1,
        "_preconValue2": -1,
        "_errerstringid": -1,
        "_setCptype": SET_CPTYPE,
        "_setCombatpower": _f32(SET_COMBATPOWER),
    }


def build_set_skill_row() -> dict[str, Any]:
    """Build the skilldata row for the mark's set-effect passive skill."""
    return {
        "_skillId": ALEX_SET_SKILL_ID,
        "_skillName": ALEX_SET_SKILL_NAME,
        "_creatureName": "Alex's Hero Mark set effect",
        "_skillType": 0,  # passive
        "_skillTarget": 2,  # all allies (same as Lily)
        "_targetNo": 0,
        "_range": 30,
        "_skillRangeType": 2,
        "_skillEffectRange": 30,
        "_skillEffectRangeType": 2,
        "_effectChance": 1.0,
        "_effectChanceFactor": -1.0,
        "_turnStart": 255,
        "_turnEnd": 255,
        "_skillRespawn": 255,
        "_effect01": ALEX_SET_EFFECT01_ID,
        "_effect02": ALEX_SET_EFFECT02_ID,
        "_effect03": -1,
        "_effect04": -1,
        "_cooltime": 255,
        "_useParameterKind": 0,
        "_useParameter": -1,
        "_heightAttack": 255,
        "_tooltip": (
            "Increases all allies' Final Skill Power by [41FF3A]{0}%[FFFFFF]. "
            "While at least 1 ally is alive, increases all allies' Attack by "
            "[41FF3A]{1}%[FFFFFF].@1-3@2-3"
        ),
        "_iconName": "-1",
        "_precondition": "-1",
    }


def build_set_effect_rows(by_id: dict[int, dict[str, Any]]) -> list[dict[str, Any]]:
    """Build the skilleffecttable rows for the mark's set effects."""
    import copy

    # Effect 1: team-wide +20% Final Skill Power (type 68, unconditional)
    final_power = copy.deepcopy(by_id[DONOR_FINAL_POWER_BUFF])
    final_power.update(
        _skillEffectId=ALEX_SET_EFFECT01_ID,
        _effectTarget=2,  # all allies
        _precondition=255,
        _preconValue=_f32(-1.0),
        _preconValue2=-1,
        _effectValue=_f32(0.20),
        _effectValueFactor=_f32(0.0),
        _effectValueType=2,
    )

    # Effect 2: +10% Attack with >=1 ally alive (type 58, precon 72)
    ap_up = copy.deepcopy(by_id[DONOR_AP_UP_RATE])
    ap_up.update(
        _skillEffectId=ALEX_SET_EFFECT02_ID,
        _effectTarget=2,  # all allies
        _precondition=72,  # CasterAllyCountIsGreaterThan
        _preconValue=_f32(1.0),
        _preconValue2=-1,
        _effectValue=_f32(0.10),
        _effectValueFactor=_f32(0.0),
        _effectValueType=2,
    )

    return [final_power, ap_up]


DONOR_MARK_SOULGEAR_ID = 285749520  # Thanatos's mark row (parts=3, the structural donor)


def patch_soulgeartable_rows(rows: list[dict[str, Any]], locale_suffix: str) -> int:
    """Add Alex's mark row to the soulgeartable by cloning the Thanatos donor row."""
    import copy

    existing = [r for r in rows if int(r.get("_soulgearId", -1)) == ALEX_MARK_SOULGEAR_ID]
    if existing:
        if len(existing) != 1:
            raise ValueError(f"soulgeartable{locale_suffix} has duplicate mark row {ALEX_MARK_SOULGEAR_ID}")
        row = existing[0]
        if (
            int(row.get("_creatureId", -1)) != ALEX_CREATURE_ID
            or int(row.get("_skillGroupId", -1)) != ALEX_MARK_SKILL_GROUP_ID
            or int(row.get("_setgroupid", -1)) != ALEX_MARK_SET_GROUP_ID
            or row.get("_icon") != ALEX_MARK_ICON
            or row.get("_iconFolder") != ALEX_MARK_ICON_FOLDER
            or row.get("_name") != ALEX_MARK_NAME
        ):
            raise ValueError(f"soulgeartable{locale_suffix} has conflicting row {ALEX_MARK_SOULGEAR_ID}")
        return 0
    # Find the Thanatos mark row (parts=3 donor) and clone it
    donor = next(
        (r for r in rows if int(r.get("_soulgearId", -1)) == DONOR_MARK_SOULGEAR_ID),
        None,
    )
    if donor is None:
        raise ValueError(f"soulgeartable{locale_suffix} missing donor mark row {DONOR_MARK_SOULGEAR_ID}")
    mark = copy.deepcopy(donor)
    mark.update(
        _soulgearId=ALEX_MARK_SOULGEAR_ID,
        _creatureId=ALEX_CREATURE_ID,
        _name=ALEX_MARK_NAME,
        _skillGroupId=ALEX_MARK_SKILL_GROUP_ID,
        _setgroupid=ALEX_MARK_SET_GROUP_ID,
        _icon=ALEX_MARK_ICON,
        _iconFolder=ALEX_MARK_ICON_FOLDER,
    )
    rows.append(mark)
    return 1


DONOR_SET_GROUP_ID = 30041  # Lily's mark set row (the two-effect structure donor)


def patch_setitemtable_rows(rows: list[dict[str, Any]], locale_suffix: str) -> int:
    """Add (or repair) Alex's mark set row in ``setitemtable``.

    The row is built deterministically instead of cloned from a donor: cloning
    kept the donor's text fields, and the previous revision reused set group
    ``30048``, which the stock tables already assign to the "Vampire" set — the
    patcher saw the id taken, skipped its row, and the client displayed the
    Vampire set as Alex's mark.
    """
    row = build_set_row(ALEX_MARK_NAME)
    existing = [r for r in rows if int(r.get("_setgroupid", -1)) == ALEX_MARK_SET_GROUP_ID]
    if existing:
        foreign = [r for r in existing if str(r.get("_setName")) != ALEX_MARK_NAME]
        if foreign:
            raise ValueError(
                f"setitemtable{locale_suffix} set group {ALEX_MARK_SET_GROUP_ID} is already "
                f"used by {foreign[0].get('_setName')!r}"
            )
        if len(existing) == 1 and all(existing[0].get(k) == v for k, v in row.items()):
            return 0
        rows[:] = [r for r in rows if int(r.get("_setgroupid", -1)) != ALEX_MARK_SET_GROUP_ID]
    rows.append(row)
    return 1


def patch_overlap_rows(rows: list[dict[str, Any]]) -> int:
    """Add Alex's mark overlap group rows to the skilloverlaptable if absent."""
    existing = [r for r in rows if int(r.get("_groupId", -1)) == ALEX_MARK_SKILL_GROUP_ID]
    if existing:
        expected = build_overlap_rows()
        if len(existing) != len(expected) or any(
            sum(all(r.get(k) == v for k, v in wanted.items()) for r in existing) != 1
            for wanted in expected
        ):
            raise ValueError("Alex's mark overlap group differs from the expected rows")
        return 0
    rows.extend(build_overlap_rows())
    return len(OVERLAP_LEVELS)


DONOR_SET_SKILL_ID = 11556949  # Lily's mark set skill (the passive with two effects)


def patch_set_skilldata_rows(rows: list[dict[str, Any]]) -> int:
    """Add the mark's set-effect passive skill (clone Lily's or build from scratch)."""
    import copy

    existing = [r for r in rows if int(r.get("_skillId", -1)) == ALEX_SET_SKILL_ID]
    if existing:
        expected = build_set_skill_row()
        if len(existing) != 1 or any(existing[0].get(k) != v for k, v in expected.items()):
            raise ValueError("Alex's mark set skill differs from the expected row")
        return 0
    donor = next(
        (r for r in rows if int(r.get("_skillId", -1)) == DONOR_SET_SKILL_ID),
        None,
    )
    ours = build_set_skill_row()
    if donor is not None:
        skill = copy.deepcopy(donor)
        skill.update(ours)
    else:
        skill = dict(ours)
    rows.append(skill)
    return 1


def patch_set_effect_rows(rows: list[dict[str, Any]]) -> int:
    """Add the mark's set-effect rows by cloning same-type donors or building from scratch."""
    import copy

    added = 0
    existing_ids = {int(r.get("_skillEffectId", -1)) for r in rows}
    for eid in (ALEX_SET_EFFECT01_ID, ALEX_SET_EFFECT02_ID):
        if eid not in existing_ids:
            added += 1
    if added == 0:
        if not _has_valid_mark_effects(rows):
            raise ValueError("Alex's mark set effects differ from the expected rows")
        return 0
    if added != 2:
        raise ValueError("Alex's mark set effects are incomplete")

    # Effect 1: team-wide +20% Final Skill Power (prefer Lily's donor; fall back
    # to any type-68 row for locales that omit newer heroes, or build from scratch)
    donor1 = next(
        (r for r in rows if int(r.get("_skillEffectId", -1)) == DONOR_FINAL_POWER_BUFF),
        None,
    ) or next(
        (r for r in rows if int(r.get("_skillEffectType", -1)) == 68),
        None,
    )
    if donor1 is not None:
        final_power = copy.deepcopy(donor1)
        final_power.update(
            _skillEffectId=ALEX_SET_EFFECT01_ID,
            _effectTarget=2,
            _precondition=255,
            _preconValue=_f32(-1.0),
            _preconValue2=-1,
            _effectValue=_f32(0.20),
            _effectValueFactor=_f32(0.0),
            _effectValueType=2,
            _effectIcon="B_SkillIcon_68",
            _effectString="Final Power Up",
        )
    else:
        final_power = {
            "_skillEffectId": ALEX_SET_EFFECT01_ID,
            "_effectName": "Final Skill Power % Increase - Buff",
            "_skillEffectType": 68,
            "_effectTarget": 2,
            "_precondition": 255,
            "_preconValue": _f32(-1.0),
            "_preconValue2": -1,
            "_linkSkillType": 255,
            "_linkSkillId": -1,
            "_parameterKind": 255,
            "_effectValueType": 2,
            "_effectValue": _f32(0.20),
            "_effectValueFactor": _f32(0.0),
            "_maxParameterValue": _f32(-1.0),
            "_effectChance": _f32(-1.0),
            "_effectChanceFactor": _f32(-1.0),
            "_skillAffectedType": 4,
            "_panelType": 2,
            "_effectDuplicate": 1,
            "_effectOverlap": 1,
            "_skillIcon": "D_SkillIcon_33",
            "_effectIcon": "B_SkillIcon_68",
            "_effectFxPrefab": "ETC_Buff_01",
            "_dispelAllow": 255,
            "_effectString": "Final Power Up",
        }

    # Effect 2: +10% Attack with >=1 ally — prefer DONOR_AP_UP_RATE, else any type-58 row
    donor2 = next(
        (r for r in rows if int(r.get("_skillEffectId", -1)) == DONOR_AP_UP_RATE and int(r.get("_skillEffectType", -1)) == 58),
        None,
    ) or next(
        (r for r in rows if int(r.get("_skillEffectType", -1)) == 58),
        None,
    )
    if donor2 is not None:
        ap_up = copy.deepcopy(donor2)
        ap_up.update(
            _skillEffectId=ALEX_SET_EFFECT02_ID,
            _effectTarget=2,
            _precondition=72,
            _preconValue=_f32(1.0),
            _preconValue2=-1,
            _effectValue=_f32(0.10),
            _effectValueFactor=_f32(0.0),
            _effectValueType=2,
        )
    else:
        ap_up = {
            "_skillEffectId": ALEX_SET_EFFECT02_ID,
            "_effectName": "Attack % Increase",
            "_skillEffectType": 58,
            "_effectTarget": 2,
            "_precondition": 72,
            "_preconValue": _f32(1.0),
            "_preconValue2": -1,
            "_linkSkillType": 255,
            "_linkSkillId": -1,
            "_parameterKind": 255,
            "_effectValueType": 2,
            "_effectValue": _f32(0.10),
            "_effectValueFactor": _f32(0.0),
            "_maxParameterValue": _f32(-1.0),
            "_effectChance": _f32(-1.0),
            "_effectChanceFactor": _f32(-1.0),
            "_skillAffectedType": 4,
            "_panelType": 2,
            "_effectDuplicate": 1,
            "_effectOverlap": 1,
            "_skillIcon": "D_SkillIcon_29",
            "_effectIcon": "B_SkillIcon_58",
            "_effectFxPrefab": "ETC_Buff_01",
            "_dispelAllow": 255,
            "_effectString": "Attack Up",
        }

    for nr in (final_power, ap_up):
        eid = int(nr["_skillEffectId"])
        if eid not in existing_ids:
            rows.append(nr)
    return added


def inspect_alex_heros_mark_assets(archive: zipfile.ZipFile) -> tuple[bool, str]:
    """Independently verify all pieces of Alex's Hero's Mark."""
    try:
        import cryptography  # noqa: F401
        import UnityPy  # noqa: F401
    except ImportError:
        return False, "Optional dependencies (UnityPy/cryptography) not available"

    from core.apk_tooling import _read_datatable_rows

    names = archive.namelist()
    details: list[str] = []
    all_ok = True

    locales = ("", "chinese", "english", "german", "japanese", "spanish", "thai", "vietnamese")

    # 1. Mark row in soulgeartable (all 8 locales, reusing Thanatos's icon)
    sg_ok = 0
    for suffix in locales:
        path = f"files/Resources/datatable/soulgeartable{suffix}.unity3d"
        if path not in names:
            all_ok = False
            details.append(f"missing {Path(path).name}")
            continue
        rows, err = _read_datatable_rows(archive, path, label=Path(path).name)
        if err or rows is None:
            all_ok = False
            details.append(f"{Path(path).name}: {err or 'no rows'}")
            continue
        found = [
            r for r in rows
            if int(r.get("_soulgearId", -1)) == ALEX_MARK_SOULGEAR_ID
            and int(r.get("_creatureId", -1)) == ALEX_CREATURE_ID
            and int(r.get("_skillGroupId", -1)) == ALEX_MARK_SKILL_GROUP_ID
            and int(r.get("_setgroupid", -1)) == ALEX_MARK_SET_GROUP_ID
            and r.get("_name") == ALEX_MARK_NAME
            and r.get("_icon") == ALEX_MARK_ICON
            and r.get("_iconFolder") == ALEX_MARK_ICON_FOLDER
        ]
        if len(found) == 1:
            sg_ok += 1
        else:
            all_ok = False
    details.append(f"mark row: {sg_ok}/8 locales")

    # 2. Overlap rows (all 8 locales)
    ov_ok = 0
    for suffix in locales:
        path = f"files/Resources/datatable/skilloverlaptable{suffix}.unity3d"
        if path not in names:
            all_ok = False
            details.append(f"missing {Path(path).name}")
            continue
        rows, _err = _read_datatable_rows(archive, path, label=Path(path).name)
        if rows is None:
            rows = []
        matching = [
            r for r in rows
            if int(r.get("_groupId", -1)) == ALEX_MARK_SKILL_GROUP_ID
            and int(r.get("_skillId", -1)) == DESTINY_LANCE_SKILL_ID
            and int(r.get("_effect01ExtravalueType", -1)) == OVERLAP_BOOST_TYPE
            and _is_close(
                r.get("_effect01Extravalue", 0.0),
                _f32(OVERLAP_BOOST_PER_LEVEL * int(r.get("_equipLevel", -1))),
            )
            and r.get("_desEquip") == overlap_description(int(r.get("_equipLevel", -1)))
        ]
        levels = {int(r.get("_equipLevel", -1)) for r in matching}
        if len(matching) == len(OVERLAP_LEVELS) and levels == set(OVERLAP_LEVELS):
            ov_ok += 1
        else:
            all_ok = False
    details.append(f"overlap group {ALEX_MARK_SKILL_GROUP_ID}: {ov_ok}/8 locales")

    # 3. Set row (all 8 locales)
    st_ok = 0
    for suffix in locales:
        path = f"files/Resources/datatable/setitemtable{suffix}.unity3d"
        if path not in names:
            continue
        rows, _err = _read_datatable_rows(archive, path, label=Path(path).name)
        st_found = rows is not None and any(
            int(r.get("_setgroupid", -1)) == ALEX_MARK_SET_GROUP_ID
            and str(r.get("_setName")) == ALEX_MARK_NAME
            and int(r.get("_setSkillid01", -1)) == ALEX_SET_SKILL_ID
            for r in rows
        )
        if st_found:
            st_ok += 1
    details.append(f"set row: {st_ok}/8 locales")
    if st_ok != 8:
        all_ok = False

    # 4. Set skill in skilldata (all 8 locales) + Destiny Lance keeps stock cooltime=1
    sd_ok = 0
    cooltime_stock_ok = True
    for suffix in locales:
        path = f"files/Resources/datatable/skilldata{suffix}.unity3d"
        if path not in names:
            continue
        rows, _err = _read_datatable_rows(archive, path, label=Path(path).name)
        if rows is None:
            continue
        expected_skill = build_set_skill_row()
        ours = next((r for r in rows if int(r.get("_skillId", -1)) == ALEX_SET_SKILL_ID), None)
        if (
            ours is not None
            and str(ours.get("_tooltip")) == str(expected_skill["_tooltip"])
            and int(ours.get("_effect01", -1)) == int(expected_skill["_effect01"])
            and int(ours.get("_effect02", -1)) == int(expected_skill["_effect02"])
            and int(ours.get("_skillTarget", -1)) == int(expected_skill["_skillTarget"])
            and int(ours.get("_skillType", -1)) == int(expected_skill["_skillType"])
        ):
            sd_ok += 1
        for r in rows:
            if int(r.get("_skillId", -1)) == DESTINY_LANCE_SKILL_ID:
                if int(r.get("_cooltime", -1)) != DESTINY_LANCE_COOLTIME_STOCK:
                    cooltime_stock_ok = False
                break
    details.append(f"set skill: {sd_ok}/8 locales")
    if sd_ok != 8:
        all_ok = False
    details.append(f"Destiny Lance base cooltime=1: {'ok' if cooltime_stock_ok else 'modified'}")
    if not cooltime_stock_ok:
        all_ok = False

    # 5. Set effects in skilleffecttable (all 8 locales)
    et_ok = 0
    for suffix in locales:
        path = f"files/Resources/datatable/skilleffecttable{suffix}.unity3d"
        if path not in names:
            continue
        rows, _err = _read_datatable_rows(archive, path, label=Path(path).name)
        if rows is None:
            continue
        if _has_valid_mark_effects(rows):
            et_ok += 1
    details.append(f"set effects: {et_ok}/8 locales")
    if et_ok != 8:
        all_ok = False

    return all_ok, "; ".join(details)


def prepare_alex_heros_mark_assets(
    archive: zipfile.ZipFile,
    *,
    existing_replacements: dict[str, bytes] | None = None,
) -> tuple[dict[str, bytes], dict[str, bytes]]:
    """Patch all mark-related bundles and return (replacements, additions)."""
    import re

    from core.alex_rebalance import _save_and_verify_bundle  # reuse the proven round-trip helper

    names = archive.namelist()

    def read_bundle(path: str) -> bytes:
        if existing_replacements and path in existing_replacements:
            return existing_replacements[path]
        return archive.read(path)

    def _suffix(path: str) -> str:
        m = re.search(r"datatable/soulgeartable(\w*)\.unity3d", path)
        return m.group(1) if m else ""

    replacements: dict[str, bytes] = {}
    total_changes = 0

    # 1. Patch soulgeartable (8 locales) — add mark row
    sg_paths = sorted(
        p for p in names
        if re.fullmatch(r"files/Resources/datatable/soulgeartable[a-z]*\.unity3d", p)
    )
    if len(sg_paths) != 8:
        raise ValueError(f"Expected 8 soulgeartable bundles, found {len(sg_paths)}")
    for path in sg_paths:
        suffix = _suffix(path)
        def _mutate_sg(rows: list[dict[str, Any]], _sfx: str = suffix) -> tuple[bool, list[dict[str, Any]]]:
            n = patch_soulgeartable_rows(rows, _sfx)
            return n > 0, rows
        patched = _save_and_verify_bundle(path, read_bundle(path), _mutate_sg)
        if patched is not None:
            replacements[path] = patched
            total_changes += 1

    # 2. Patch setitemtable (8 locales) — add set row
    st_paths = sorted(
        p for p in names
        if re.fullmatch(r"files/Resources/datatable/setitemtable[a-z]*\.unity3d", p)
    )
    if len(st_paths) != 8:
        raise ValueError(f"Expected 8 setitemtable bundles, found {len(st_paths)}")
    for path in st_paths:
        m2 = re.search(r"setitemtable(\w*)\.unity3d", path)
        st_suffix = m2.group(1) if m2 else ""
        def _mutate_st(rows: list[dict[str, Any]], _sfx: str = st_suffix) -> tuple[bool, list[dict[str, Any]]]:
            n = patch_setitemtable_rows(rows, _sfx)
            return n > 0, rows
        patched = _save_and_verify_bundle(path, read_bundle(path), _mutate_st)
        if patched is not None:
            replacements[path] = patched
            total_changes += 1

    # 3. Patch skilloverlaptable (8 locales) — add overlap group rows
    ov_paths = sorted(
        p for p in names
        if re.fullmatch(r"files/Resources/datatable/skilloverlaptable[a-z]*\.unity3d", p)
    )
    if len(ov_paths) != 8:
        raise ValueError(f"Expected 8 skilloverlaptable bundles, found {len(ov_paths)}")
    for path in ov_paths:
        def _mutate_ov(rows: list[dict[str, Any]]) -> tuple[bool, list[dict[str, Any]]]:
            n = patch_overlap_rows(rows)
            return n > 0, rows
        patched = _save_and_verify_bundle(path, read_bundle(path), _mutate_ov)
        if patched is not None:
            replacements[path] = patched
            total_changes += 1

    # 4. Patch skilldata (8 locales) — add set skill (leave Destiny Lance cooltime at stock 1)
    sd_paths = sorted(
        p for p in names
        if re.fullmatch(r"files/Resources/datatable/skilldata[a-z]*\.unity3d", p)
    )
    if len(sd_paths) != 8:
        raise ValueError(f"Expected 8 skilldata bundles, found {len(sd_paths)}")
    for path in sd_paths:
        def _mutate_sd(rows: list[dict[str, Any]]) -> tuple[bool, list[dict[str, Any]]]:
            n1 = patch_set_skilldata_rows(rows)
            return n1 > 0, rows
        patched = _save_and_verify_bundle(path, read_bundle(path), _mutate_sd)
        if patched is not None:
            replacements[path] = patched
            total_changes += 1

    # 5. Patch skilleffecttable (8 locales) — add set effect rows
    et_paths = sorted(
        p for p in names
        if re.fullmatch(r"files/Resources/datatable/skilleffecttable[a-z]*\.unity3d", p)
    )
    if len(et_paths) != 8:
        raise ValueError(f"Expected 8 skilleffecttable bundles, found {len(et_paths)}")
    for path in et_paths:
        def _mutate_et(rows: list[dict[str, Any]]) -> tuple[bool, list[dict[str, Any]]]:
            n = patch_set_effect_rows(rows)
            return n > 0, rows
        patched = _save_and_verify_bundle(path, read_bundle(path), _mutate_et)
        if patched is not None:
            replacements[path] = patched
            total_changes += 1

    if total_changes == 0:
        return {}, {}
    return replacements, {}


# ---------------------------------------------------------------------------
# Native .so patches (server fwt_valid_soulgear_idx + client Lv10 cooltime)
# ---------------------------------------------------------------------------

ALEX_MARK_SERVER_CAVE_VADDR = 0xB2AFDC  # free tail of parseType (..0xB2B098)
ALEX_MARK_SERVER_CAVE_SIZE = 5 * 28     # 140 bytes (ends 0xB2B068)

ALEX_MARK_CLIENT_CAVE_VADDR = 0xB2FAA0  # free tail of parseExpr (..0xB2FBA0)
ALEX_MARK_CLIENT_CAVE_MAX_SIZE = 256    # 0xB2FAA0..0xB2FBA0

# Post-Covault installer site: the conditional branch that splits the common
# exit path of the covault permission-finalization flow. Every boot passes
# through it, in both directions: ``w19 == 0`` jumps to the fire-support hook
# (0xAB335C), otherwise the flow falls through to 0xAB3308 and on to the log
# call. Its neighbouring sites are already owned (0xAB335C fire support,
# 0xAB3378 Alex Awakening, 0xAB337C battle_arena_save_fix, 0xAB3380+ the
# client epilogue chain), so this is the first free instruction on the path.
# Hooking here also clobbers only scratch registers: x0-x5 are rewritten by
# the block right after it, so the installer needs no register saves.
ALEX_MARK_CLIENT_INSTALL_SITE = 0xAB3304
ALEX_MARK_CLIENT_INSTALL_STOCK = bytes.fromhex("d3020034")  # cbz w19, #0xab335c
ALEX_MARK_CLIENT_INSTALL_W19_ZERO = 0xAB335C  # stock branch target for w19 == 0

# Five inlined fwt_valid_soulgear_idx::kIds loop-exit branches in libfwt_local_server.so
# (site_va, reg_name, found_va, not_found_va)
KIDS_HOOK_SITES: tuple[tuple[int, str, int, int], ...] = (
    (0x7EBDEC, "x0", 0x7EC204, 0x7EC38C),
    (0x7EC814, "x19", 0x7ED340, 0x7ED414),
    (0x8B08A4, "x21", 0x8B08A8, 0x8B0998),
    (0x9A027C, "x0", 0x9A0280, 0x9A04C0),
    (0xA1B42C, "x0", 0xA1B430, 0xA1B474),
)

# Client RVA: Skill::GetCurrentCoolTime (awakening skill branch)
CLIENT_GET_COOLTIME_RVA = 0x16064B4
CLIENT_GET_COOLTIME_CONT_RVA = 0x16064C4
CLIENT_GET_COOLTIME_EXPECTED_WORDS: tuple[int, int, int, int] = (
    0xD10203FF,  # sub sp, sp, #0x80
    0xFD0023E8,  # str d8, [sp, #0x40]
    0xF90027F7,  # str x23, [sp, #0x48]
    0xA90557F6,  # stp x22, x21, [sp, #0x50]
)
PATCH_IL2CPP_HELPER = 0xAB575C
IL2CPP_BASE_CACHE = 0xBE3798


def _asm_arm64(source: str, base_addr: int) -> bytes:
    from keystone import KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, Ks

    ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
    encoding, _ = ks.asm(source, base_addr)
    if encoding is None:
        raise RuntimeError(f"Keystone failed to assemble at {base_addr:#x}")
    return bytes(encoding)


def build_alex_heros_mark_server_cave() -> tuple[list[tuple[int, bytes, bytes]], bytes]:
    """Build (site_patches, server_cave_bytes) for the 5 kIds validation sites."""
    site_patches: list[tuple[int, bytes, bytes]] = []
    cave_chunks: list[bytes] = []
    lo = ALEX_MARK_SOULGEAR_ID & 0xFFFF
    hi = (ALEX_MARK_SOULGEAR_ID >> 16) & 0xFFFF

    for idx, (site_va, reg, found_va, not_found_va) in enumerate(KIDS_HOOK_SITES):
        stub_va = ALEX_MARK_SERVER_CAVE_VADDR + idx * 28
        stock_br = _asm_arm64(f"b {not_found_va:#x}", site_va)
        hook_br = _asm_arm64(f"b {stub_va:#x}", site_va)
        stub_src = (
            f"movz x10, #{lo:#x}\n"
            f"movk x10, #{hi:#x}, lsl #16\n"
            f"cmp x10, {reg}\n"
            f"b.ne not_found\n"
            f"mov x8, xzr\n"
            f"b {found_va:#x}\n"
            f"not_found:\n"
            f"b {not_found_va:#x}\n"
        )
        stub_bytes = _asm_arm64(stub_src, stub_va)
        if len(stub_bytes) != 28:
            raise AssertionError(f"Expected 28B stub at {stub_va:#x}, got {len(stub_bytes)}B")
        site_patches.append((site_va, stock_br, hook_br))
        cave_chunks.append(stub_bytes)

    cave_bytes = b"".join(cave_chunks)
    if len(cave_bytes) != ALEX_MARK_SERVER_CAVE_SIZE:
        raise AssertionError(
            f"Server cave size mismatch: {len(cave_bytes)} != {ALEX_MARK_SERVER_CAVE_SIZE}"
        )
    return site_patches, cave_bytes


def build_alex_heros_mark_client_cave() -> tuple[bytes, bytes]:
    """Build (install_bl_4B, client_cave_bytes) for Lv10 Destiny Lance cooldown=0.

    The cave holds two entry points: the post-Covault installer that calls
    ``PATCH_IL2CPP_HELPER`` once per boot (``ALEX_MARK_CLIENT_INSTALL_SITE``),
    and the payload that replaces the client's ``Skill::GetCurrentCoolTime``
    prologue and either returns cooltime 0 for a Lv10 mark or replays the
    displaced instructions and continues in ``libil2cpp.so``.
    """
    page = IL2CPP_BASE_CACHE & ~0xFFF
    page_off = IL2CPP_BASE_CACHE & 0xFFF
    skill_lo = DESTINY_LANCE_SKILL_ID & 0xFFFF
    skill_hi = (DESTINY_LANCE_SKILL_ID >> 16) & 0xFFFF
    cont_lo = CLIENT_GET_COOLTIME_CONT_RVA & 0xFFFF
    cont_hi = (CLIENT_GET_COOLTIME_CONT_RVA >> 16) & 0xFFFF
    rva_lo = CLIENT_GET_COOLTIME_RVA & 0xFFFF
    rva_hi = (CLIENT_GET_COOLTIME_RVA >> 16) & 0xFFFF

    exp_words_asm = "\n".join(f"    .word {w:#010x}" for w in CLIENT_GET_COOLTIME_EXPECTED_WORDS)
    source = f"""
installer_entry:
    stp  x29, x30, [sp, #-0x20]!
    adrp x9, {page:#x}
    ldr  x0, [x9, #{page_off:#x}]
    cbz  x0, installer_done
    movz w1, #{rva_lo:#x}
    movk w1, #{rva_hi:#x}, lsl #16
    adr  x2, exp_words
    adr  x3, tramp_blob
    ldr  x9, [x3]
    str  x9, [sp, #0x10]
    adr  x9, payload_entry
    str  x9, [sp, #0x18]
    add  x3, sp, #0x10
    mov  w4, #4
    adr  x5, hook_name
    bl   {PATCH_IL2CPP_HELPER:#x}
installer_done:
    ldp  x29, x30, [sp], #0x20
    cbnz w19, installer_return
    b    {ALEX_MARK_CLIENT_INSTALL_W19_ZERO:#x}
installer_return:
    ret

payload_entry:
    cbz  x0, fallthrough
    ldr  x8, [x0, #0x18]
    cbz  x8, fallthrough
    ldr  w9, [x8, #0x10]
    movz w10, #{skill_lo:#x}
    movk w10, #{skill_hi:#x}, lsl #16
    cmp  w9, w10
    b.ne fallthrough
    ldr  x8, [x0, #0x10]
    cbz  x8, fallthrough
    ldr  x8, [x8, #0x20]
    cbz  x8, fallthrough
    stp  x0, x30, [sp, #-0x10]!
    mov  x0, x8
    ldr  x8, [x0]
    mov  w1, #3
    ldr  x9, [x8, #0xa40]
    ldr  x2, [x8, #0xa48]
    blr  x9
    ldp  x10, x30, [sp], #0x10
    cbz  x0, restore_fallthrough
    ldr  w8, [x0, #0x30]
    cmp  w8, #10
    b.lt restore_fallthrough
    mov  w0, wzr
    ret
restore_fallthrough:
    mov  x0, x10
fallthrough:
    sub  sp, sp, #0x80
    str  d8, [sp, #0x40]
    str  x23, [sp, #0x48]
    stp  x22, x21, [sp, #0x50]
    adrp x16, {page:#x}
    ldr  x16, [x16, #{page_off:#x}]
    movz x17, #{cont_lo:#x}
    movk x17, #{cont_hi:#x}, lsl #16
    add  x16, x16, x17
    br   x16

.p2align 2
tramp_blob:
    .word 0x58000050
    .word 0xd61f0200
exp_words:
{exp_words_asm}
hook_name:
    .asciz "mk"
"""
    cave_bytes = _asm_arm64(source, ALEX_MARK_CLIENT_CAVE_VADDR)
    if len(cave_bytes) > ALEX_MARK_CLIENT_CAVE_MAX_SIZE:
        raise AssertionError(
            f"Alex mark client cave ({len(cave_bytes)}B) exceeds {ALEX_MARK_CLIENT_CAVE_MAX_SIZE}B"
        )
    install_bl = _asm_arm64(f"bl {ALEX_MARK_CLIENT_CAVE_VADDR:#x}", ALEX_MARK_CLIENT_INSTALL_SITE)
    return install_bl, cave_bytes


ALEX_MARK_SERVER_CAVE_ORIGINAL_SHA256 = (
    "ad1c13351f18ce248377e3e225dd392120372470b5be28c810d7f4fdfabe4055"
)
ALEX_MARK_CLIENT_CAVE_ORIGINAL_SHA256 = (
    "be899379ce885fe579ba1732c6bf2e12255124175da9cc0b447e515a48e22989"
)


def apply_alex_heros_mark_so(
    so_buf: bytearray,
    seg_offset: Any,
) -> int:
    """Apply server kIds cave + client Lv10 cooltime hook to libfwt_local_server.so."""
    import hashlib

    site_patches, server_cave = build_alex_heros_mark_server_cave()
    install_bl, client_cave = build_alex_heros_mark_client_cave()

    states: list[str] = []
    for site_va, stock_br, hook_br in site_patches:
        off = seg_offset(site_va, 4) if _accepts_size(seg_offset) else seg_offset(site_va)
        cur = bytes(so_buf[off:off + 4])
        if cur == stock_br:
            states.append("stock")
        elif cur == hook_br:
            states.append("patched")
        else:
            raise ValueError(
                f"Unexpected bytes at kIds site {site_va:#x}: {cur.hex()} "
                f"(expected {stock_br.hex()})"
            )

    inst_off = seg_offset(ALEX_MARK_CLIENT_INSTALL_SITE)
    cur_inst = bytes(so_buf[inst_off:inst_off + 4])
    if cur_inst == ALEX_MARK_CLIENT_INSTALL_STOCK:
        states.append("stock")
    elif cur_inst == install_bl:
        states.append("patched")
    else:
        raise ValueError(
            f"Unexpected bytes at client install site {ALEX_MARK_CLIENT_INSTALL_SITE:#x}: "
            f"{cur_inst.hex()} (expected {ALEX_MARK_CLIENT_INSTALL_STOCK.hex()})"
        )

    srv_cave_off = seg_offset(ALEX_MARK_SERVER_CAVE_VADDR)
    cur_srv_cave = bytes(so_buf[srv_cave_off:srv_cave_off + len(server_cave)])
    if cur_srv_cave == server_cave:
        states.append("patched")
    elif hashlib.sha256(cur_srv_cave).hexdigest() == ALEX_MARK_SERVER_CAVE_ORIGINAL_SHA256:
        states.append("stock")
    else:
        raise ValueError("Unexpected bytes in Alex's Hero's Mark server cave")

    cli_cave_off = seg_offset(ALEX_MARK_CLIENT_CAVE_VADDR)
    cur_cli_cave = bytes(so_buf[cli_cave_off:cli_cave_off + len(client_cave)])
    if cur_cli_cave == client_cave:
        states.append("patched")
    elif hashlib.sha256(cur_cli_cave).hexdigest() == ALEX_MARK_CLIENT_CAVE_ORIGINAL_SHA256:
        states.append("stock")
    else:
        raise ValueError("Unexpected bytes in Alex's Hero's Mark client cave")

    if len(set(states)) != 1:
        raise ValueError("Unexpected or partially patched Alex's Hero's Mark native code")
    if states[0] == "patched":
        return 0

    applied = 0
    so_buf[srv_cave_off:srv_cave_off + len(server_cave)] = server_cave
    applied += 1
    for site_va, _stock_br, hook_br in site_patches:
        off = seg_offset(site_va)
        so_buf[off:off + 4] = hook_br
        applied += 1

    so_buf[cli_cave_off:cli_cave_off + len(client_cave)] = client_cave
    applied += 1
    so_buf[inst_off:inst_off + 4] = install_bl
    applied += 1

    return applied


def _accepts_size(seg_offset: Any) -> bool:
    import inspect
    try:
        return len(inspect.signature(seg_offset).parameters) >= 2
    except (TypeError, ValueError):
        return False


def inspect_alex_heros_mark_so(
    so_bytes: bytes | bytearray,
    seg_offset: Any,
) -> tuple[bool, str]:
    """Verify server kIds cave + client Lv10 cooltime hook in libfwt_local_server.so."""
    site_patches, server_cave = build_alex_heros_mark_server_cave()
    install_bl, client_cave = build_alex_heros_mark_client_cave()

    srv_cave_off = seg_offset(ALEX_MARK_SERVER_CAVE_VADDR)
    srv_cave_ok = bytes(so_bytes[srv_cave_off:srv_cave_off + len(server_cave)]) == server_cave
    sites_ok = sum(
        1 for site_va, _stock, hook_br in site_patches
        if bytes(so_bytes[seg_offset(site_va):seg_offset(site_va) + 4]) == hook_br
    )

    cli_cave_off = seg_offset(ALEX_MARK_CLIENT_CAVE_VADDR)
    cli_cave_ok = bytes(so_bytes[cli_cave_off:cli_cave_off + len(client_cave)]) == client_cave
    inst_off = seg_offset(ALEX_MARK_CLIENT_INSTALL_SITE)
    inst_ok = bytes(so_bytes[inst_off:inst_off + 4]) == install_bl

    ok = srv_cave_ok and sites_ok == len(site_patches) and cli_cave_ok and inst_ok
    detail = (
        f"kIds sites={sites_ok}/{len(site_patches)}, "
        f"srv_cave={'ok' if srv_cave_ok else 'missing'}, "
        f"cli_cave={'ok' if cli_cave_ok else 'missing'}, "
        f"cli_hook={'ok' if inst_ok else 'missing'}"
    )
    return ok, detail
