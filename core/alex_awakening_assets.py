"""Client resource construction for the experimental Alex Awakening.

The reference tables are checked and round-tripped before output is returned.
"""

from __future__ import annotations

import copy
import hashlib
import re
import zipfile
from typing import Any

_PATH = "files/Resources/datatable/creaturerebirth.unity3d"

_REFERENCE_SHA256 = "45dd51a62066ed7aa5b09e172c45271dd3e283c11df9ebe29c29203f3ef36206"

_ALEX_FIVE = 0x130185

_ALEX_SIX = 0x130186

def _patch_gate(data: bytes) -> bytes:
    import UnityPy

    from core import apk_tooling

    if hashlib.sha256(data).hexdigest() != _REFERENCE_SHA256:
        raise ValueError("Unexpected reference evolution asset; refusing lab build")
    clear, key, iv = apk_tooling._decrypt_datatable(data)
    env = UnityPy.load(clear)
    objects = [obj for obj in env.objects if obj.type.name == "MonoBehaviour"]
    if len(objects) != 1:
        raise ValueError("Unexpected evolution table layout")
    tree = objects[0].read_typetree()
    rows: list[dict[str, Any]] = tree.get("_data") or []
    if len(rows) != 558 or any(row.get("_creatureId") == _ALEX_FIVE for row in rows):
        raise ValueError("Unexpected evolution rules or preexisting Alex rule")
    donors = [row for row in rows if row.get("_creatureId") == 1249317
              and row.get("_creatureId2") == 1249318 and row.get("_grade") == 5]
    if len(donors) != 1:
        raise ValueError("Expected one peer Awakening rule")
    clone = copy.deepcopy(donors[0])
    clone.update(_creatureId=_ALEX_FIVE, _creatureId2=_ALEX_SIX)
    rows.append(clone)
    objects[0].save_typetree(tree)
    encoded = apk_tooling._encrypt_datatable(bytes(getattr(env.file, "save")(packer="original")), key, iv)  # noqa: B009
    decoded, _, _ = apk_tooling._decrypt_datatable(encoded)
    found = [row for obj in UnityPy.load(decoded).objects if obj.type.name == "MonoBehaviour"
             for row in (obj.read_typetree().get("_data") or [])
             if row.get("_creatureId") == _ALEX_FIVE]
    if len(found) != 1 or found[0] != clone:
        raise ValueError("Alex client rule did not survive the asset round-trip")
    return encoded

_SKILL = 0x100185

_DAMAGE = 0x10018501

_SWAP = 21172225

def _prepare_asset(archive: zipfile.ZipFile, name: str, category: str) -> tuple[int, bytes]:
    import UnityPy

    from core.apk_tooling import _decrypt_datatable, _encrypt_datatable

    source = archive.read(f"files/Resources/datatable/{name}.unity3d")
    clear, key, iv = _decrypt_datatable(source)
    env = UnityPy.load(clear)
    objects = [obj for obj in env.objects if obj.type.name == "MonoBehaviour"]
    if len(objects) != 1:
        raise ValueError(f"Unexpected object count in {name}")
    obj = objects[0]
    tree = obj.read_typetree()
    rows: list[dict[str, Any]] = tree.get("_data") or []
    original = copy.deepcopy(rows)
    if category == "skill":
        if any(row.get("_skillId") == _SKILL for row in rows):
            raise ValueError(f"Candidate skill ID is already used in {name}")
        awake = [row for row in rows if row.get("_skillId") == 1049717]
        alex = [row for row in rows if row.get("_skillId") == 1048964]
        if not awake:
            # Some older translations predate Persona's Awakening. This is a
            # serialization fixture, so any existing Awakening has the shape.
            awake = [row for row in rows if row.get("_useParameterKind") == 5][:1]
        if len(awake) != 1 or len(alex) != 1:
            raise ValueError(f"Missing unique donor skill in {name}: "
                             f"awake={len(awake)}, alex={len(alex)}")
        row = copy.deepcopy(awake[0])
        row.update(_skillId=_SKILL, _skillName="Destiny Lance",
                   _creatureName=alex[0]["_creatureName"], _skillTarget=1,
                   _range=0, _skillRangeType=2, _skillEffectRange=0,
                   _skillEffectRangeType=0, _effect01=_DAMAGE, _effect02=_SWAP,
                   _effect03=-1, _effect04=-1, _effectChance=1.0,
                   _effectChanceFactor=-1.0, _cooltime=1, _useParameterKind=5,
                   _useParameter=-1, _turnStart=0, _turnEnd=0,
                   _tooltip="Deals [FF0000]{0}%[FFFFFF] of Attack as damage to a Boss and exchanges positions with it. Choose a Boss if more than one is present.@1-3")
        id_field, candidate = "_skillId", _SKILL
    elif category == "effect":
        if any(row.get("_skillEffectId") == _DAMAGE for row in rows):
            raise ValueError(f"Candidate effect ID is already used in {name}")
        damage = [row for row in rows if row.get("_skillEffectId") == 16847920]
        swap = [row for row in rows if row.get("_skillEffectId") == _SWAP]
        if len(damage) != 1 or len(swap) != 1:
            raise ValueError(f"Missing unique donor effect in {name}")
        row = copy.deepcopy(damage[0])
        row.update(_skillEffectId=_DAMAGE, _effectValue=2.0, _effectValueFactor=0.5)
        id_field, candidate = "_skillEffectId", _DAMAGE
    elif category == "level":
        if any(row.get("_skillId") == _SKILL for row in rows):
            raise ValueError(f"Candidate skill ID is already used in {name}")
        donors = [row for row in rows if row.get("_skillId") == 1049717]
        if len(donors) != 1:
            raise ValueError(f"Missing unique skill-level donor in {name}")
        row = copy.deepcopy(donors[0])
        row.update(_skillId=_SKILL, _maxLevel=10,
                   _level01=10, _level02=20, _level03=30, _level04=40,
                   _level05=50, _level06=60, _level07=70, _level08=80,
                   _level09=90, _level10=-1)
        id_field, candidate = "_skillId", _SKILL
    elif category == "fx":
        if any(row.get("_skillId") == _SKILL for row in rows):
            raise ValueError(f"Candidate skill ID is already used in {name}")
        donors = [row for row in rows if row.get("_creatureId") == 0x130185
                  and row.get("_skillNo") == 2]
        if len(donors) != 1:
            raise ValueError(f"Missing unique Alex FX donor in {name}")
        row = copy.deepcopy(donors[0])
        row.update(_creatureId=0x130186, _skillNo=3, _skillId=_SKILL)
        id_field, candidate = "_skillId", _SKILL
    else:
        indices = [index for index, row in enumerate(rows) if row.get("_creatureId") == 0x130186]
        if len(indices) != 1 or rows[indices[0]].get("_skill4") != -1:
            raise ValueError(f"Unexpected awakened Alex record in {name}")
        row = copy.deepcopy(rows[indices[0]])
        row["_skill4"] = _SKILL
        rows[indices[0]] = row
        id_field, candidate = "_skill4", _SKILL
    if category != "creature":
        rows.append(row)
    obj.save_typetree(tree)
    # Preserve the source bundle's compression flags. A valid UnityPy
    # round-trip alone does not prove that the device loader accepts a bundle.
    encoded = _encrypt_datatable(bytes(getattr(env.file, "save")(packer="original")), key, iv)  # noqa: B009
    reloaded, _, _ = _decrypt_datatable(encoded)
    objects = [obj for obj in UnityPy.load(reloaded).objects if obj.type.name == "MonoBehaviour"]
    if len(objects) != 1:
        raise ValueError(f"Unexpected reloaded object count in {name}")
    decoded: list[dict[str, Any]] = objects[0].read_typetree().get("_data") or []
    if category == "creature":
        original[indices[0]] = row
        expected = original
    else:
        expected = [*original, row]
    if decoded != expected:
        raise ValueError(f"Other records changed in {name}")
    if sum(item.get(id_field) == candidate for item in decoded) != 1:
        raise ValueError(f"Candidate did not round-trip in {name}")
    return len(decoded), encoded

def prepare_assets(archive: zipfile.ZipFile) -> dict[str, bytes]:
    """Prepare the localized skill records, rejecting incomplete archives."""
    result: dict[str, bytes] = {}
    for path in archive.namelist():
        match = re.fullmatch(
            r"files/Resources/datatable/((?:skilldata|skilleffecttable|creaturedata)[a-z]*"
            r"|skillleveltable|skillfxdata)\.unity3d", path
        )
        if match is None:
            continue
        name = match.group(1)
        if name.startswith("skilldata"):
            category = "skill"
        elif name.startswith("skilleffecttable"):
            category = "effect"
        elif name.startswith("creaturedata"):
            category = "creature"
        else:
            category = "level" if name == "skillleveltable" else "fx"
        if path in result:
            raise ValueError(f"Duplicate resource path: {path}")
        _, result[path] = _prepare_asset(archive, name, category)
    if len(result) != 26:
        raise ValueError(f"Expected 26 localized and shared assets, found {len(result)}")
    return result


def inspect_alex_awakening_assets(archive: zipfile.ZipFile) -> tuple[bool, str]:
    """Check the awakening rule and all localized skill records independently."""
    try:
        import cryptography  # noqa: F401
        import UnityPy
    except ImportError:
        return False, "Optional dependencies (UnityPy/cryptography) not available"

    from core.apk_tooling import _decrypt_datatable

    def rows(path: str) -> list[dict[str, Any]]:
        clear, _, _ = _decrypt_datatable(archive.read(path))
        objects = [obj for obj in UnityPy.load(clear).objects if obj.type.name == "MonoBehaviour"]
        if len(objects) != 1:
            raise ValueError(f"Unexpected table layout: {path}")
        return list(objects[0].read_typetree().get("_data") or [])

    rules = [row for row in rows(_PATH) if row.get("_creatureId") == _ALEX_FIVE]
    if len(rules) != 1 or rules[0].get("_creatureId2") != _ALEX_SIX:
        return False, "Alex awakening rule missing or incomplete"

    names = [
        path for path in archive.namelist()
        if re.fullmatch(
            r"files/Resources/datatable/((?:skilldata|skilleffecttable|creaturedata)[a-z]*"
            r"|skillleveltable|skillfxdata)\.unity3d", path
        )
    ]
    if len(names) != 26 or len(set(names)) != 26:
        return False, "Expected 26 distinct localized and shared skill tables"
    counts = {"skill": 0, "effect": 0, "creature": 0, "level": 0, "fx": 0}
    for path in names:
        name = path.rsplit("/", 1)[-1]
        table = rows(path)
        rebalanced_awake_fields: dict[str, Any] | None = None
        if name.startswith("skilldata"):
            from core.alex_rebalance import AWAKE_THORNBUSH_TOOLTIP, expected_skill_updates

            counts["skill"] += 1
            candidates = [row for row in table if row.get("_skillId") == _SKILL]
            expected = {
                "_skillName": "Destiny Lance", "_skillTarget": 1, "_range": 0,
                "_skillRangeType": 2, "_skillEffectRange": 0,
                "_skillEffectRangeType": 0, "_effect01": _DAMAGE, "_effect02": _SWAP,
                "_effect03": -1, "_effect04": -1, "_cooltime": 1,
                "_useParameterKind": 5, "_useParameter": -1,
                "_tooltip": "Deals [FF0000]{0}%[FFFFFF] of Attack as damage to a Boss and exchanges positions with it. Choose a Boss if more than one is present.@1-3",
            }
            rebalanced_awake_fields = {
                **expected,
                **expected_skill_updates(path, _SKILL, AWAKE_THORNBUSH_TOOLTIP),
            }
        elif name.startswith("skilleffecttable"):
            counts["effect"] += 1
            candidates = [row for row in table if row.get("_skillEffectId") == _DAMAGE]
            expected = {"_effectValue": 2.0, "_effectValueFactor": 0.5}
            if sum(row.get("_skillEffectId") == _SWAP for row in table) != 1:
                return False, f"Position swap effect missing in {name}"
        elif name.startswith("creaturedata"):
            counts["creature"] += 1
            candidates = [row for row in table if row.get("_creatureId") == _ALEX_SIX]
            expected = {"_skill4": _SKILL}
        elif name == "skillleveltable.unity3d":
            counts["level"] += 1
            candidates = [row for row in table if row.get("_skillId") == _SKILL]
            expected = {"_maxLevel": 10, **{f"_level{i:02d}": i * 10 for i in range(1, 10)},
                        "_level10": -1}
        else:
            counts["fx"] += 1
            candidates = [row for row in table if row.get("_skillId") == _SKILL]
            expected = {"_creatureId": _ALEX_SIX, "_skillNo": 3}
        matches_stock = len(candidates) == 1 and all(
            candidates[0].get(key) == value for key, value in expected.items()
        )
        matches_rebalanced = (
            rebalanced_awake_fields is not None
            and len(candidates) == 1
            and all(
                candidates[0].get(key) == value
                for key, value in rebalanced_awake_fields.items()
            )
        )
        if not matches_stock and not matches_rebalanced:
            return False, f"Alex awakening record missing or incomplete in {name}"
    if counts != {"skill": 8, "effect": 8, "creature": 8, "level": 1, "fx": 1}:
        return False, f"Unexpected Alex table categories: {counts}"
    return True, "Awakening rule and 26 localized/shared skill tables verified"
