"""Round-trip candidate Alex skill/effect rows in memory, without writing assets.

The geometry, targeting, damage processing, animation and server behavior are
not validated.  This is a serialization experiment, not an implementable patch.
"""

from __future__ import annotations

import argparse
import copy
import re
import zipfile
from pathlib import Path
from typing import Any

import UnityPy

from core.apk_tooling import _decrypt_datatable, _encrypt_datatable

_SKILL = 0x100185
_DAMAGE = 0x10018501
_SWAP = 21172225


def _prepare_asset(archive: zipfile.ZipFile, name: str, category: str) -> tuple[int, bytes]:
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


def _roundtrip(archive: zipfile.ZipFile, name: str, category: str) -> int:
    """Validate the fixture without saving any output."""
    count, _ = _prepare_asset(archive, name, category)
    return count


def prepare_assets(archive: zipfile.ZipFile) -> dict[str, bytes]:
    """Prepare the unvalidated fixture in memory, rejecting incomplete archives.

    These records do not implement boss targeting, animation or telemetry and
    must not be presented as a working Awake skill.
    """
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


def probe(resources: Path) -> dict[str, int]:
    result: dict[str, int] = {}
    with zipfile.ZipFile(resources) as archive:
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
            result[name] = _roundtrip(archive, name, category)
    if len(result) != 26:
        raise ValueError(f"Expected 26 localized and shared assets, found {len(result)}")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--resources", required=True, type=Path)
    args = parser.parse_args()
    result = probe(args.resources)
    print(f"Draft Awakening rows round-tripped in {len(result)} tables; no assets written.")
