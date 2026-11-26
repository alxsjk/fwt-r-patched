"""Pure asset-table patch helpers for Guild Raid Skills Max (07.07) and Boss 0% Counter (07.08)."""
from __future__ import annotations

import math
from typing import Any

GUILD_SKILL_DATA_CLIENT_ASSET_PATH = "files/Resources/datatable/guildskilldata.unity3d"
GUILD_SKILL_VALUE_FIELDS = ("_value01", "_value01Factor", "_value02", "_value02Factor")

# Effect IDs for the remaining 3 Guild Raid skills (effect 1048578 belongs to 07.06):
# - 1048577: Guild Shelling (Boss flat damage -> 1,000,000)
# - 1048579: Absolute Protection (Allies 1-hit DR -> 100%, clamped to 1.0 by GameRule)
# - 1048580: Absolute Protection & Combat Support (Allies HP restore -> 100% maxHP)
# - 1048581: Guild Shelling, Fire Support, Absolute Protection (slot 3) &
#   Combat Support (Allies MP restore -> 100% maxMP)
# - 1048582: Combat Support (RemoveDebuff -> floor((50+50)/5) = 20 removable effects)
GUILD_SKILL_INFO_CLIENT_ASSETS = (
    "files/Resources/datatable/guildskillinfo.unity3d",
    "files/Resources/datatable/guildskillinfochinese.unity3d",
    "files/Resources/datatable/guildskillinfoenglish.unity3d",
    "files/Resources/datatable/guildskillinfogerman.unity3d",
    "files/Resources/datatable/guildskillinfojapanese.unity3d",
    "files/Resources/datatable/guildskillinfospanish.unity3d",
    "files/Resources/datatable/guildskillinfothai.unity3d",
    "files/Resources/datatable/guildskillinfovietnamese.unity3d",
)
ABSOLUTE_PROTECTION_SKILL_ID = 536870915
GUILD_SKILL_MP_EFFECT_ID = 1048581
GUILD_SKILL_ALLY_TARGET = 1
ABSOLUTE_PROTECTION_STOCK_EFFECT3 = (-1, 255)
ABSOLUTE_PROTECTION_PATCHED_EFFECT3 = (GUILD_SKILL_MP_EFFECT_ID, GUILD_SKILL_ALLY_TARGET)
GUILD_SKILL_MAX_SPECS: dict[
    int, tuple[tuple[float, float, float, float], tuple[float, float, float, float]]
] = {
    1048577: ((8000.0, 1000.0, 8000.0, 1000.0), (500000.0, 0.0, 500000.0, 0.0)),
    1048579: ((0.1, 0.01, 0.1, 0.01), (0.5, 0.0, 0.5, 0.0)),
    1048580: ((0.15, 0.05, 0.15, 0.05), (0.5, 0.0, 0.5, 0.0)),
    1048581: ((0.25, 0.05, 0.25, 0.05), (0.5, 0.0, 0.5, 0.0)),
    1048582: ((5.0, 0.5, 5.0, 0.5), (50.0, 0.0, 50.0, 0.0)),
}

MONSTER_DATA_CLIENT_ASSET_PATH = "files/Resources/datatable/monsterdata.unity3d"

# All 70 Guild Raid Boss monster IDs (_boss == 100, 400-01..400-07 host + spawn levels 1..9).
# Each has stock _car = -1.0 (inheriting CreatureData._baseCar = 0.03 = 300 / 3% counter rate).
# Setting _car = 0.0 overrides CreatureData._baseCar via StatContainer$$GetBaseCARAtLevel.
GUILD_RAID_BOSS_MONSTER_IDS: frozenset[int] = frozenset({
    1073745921, 1073745922, 1073745923, 1073745924, 1073745929,
    1073745936, 1073745937, 1073745938, 1073745939, 1073745940,
    1073750017, 1073750018, 1073750019, 1073750020, 1073750025,
    1073750032, 1073750033, 1073750034, 1073750035, 1073750036,
    1073754113, 1073754114, 1073754115, 1073754116, 1073754117,
    1073754118, 1073754119, 1073754120, 1073754121, 1073754128,
    1073758209, 1073758210, 1073758211, 1073758212, 1073758213,
    1073758214, 1073758215, 1073758216, 1073758217, 1073758224,
    1073762305, 1073762306, 1073762307, 1073762308, 1073762309,
    1073762310, 1073762311, 1073762312, 1073762313, 1073762320,
    1073766401, 1073766402, 1073766403, 1073766404, 1073766409,
    1073766416, 1073766417, 1073766418, 1073766419, 1073766420,
    1073770497, 1073770498, 1073770499, 1073770500, 1073770505,
    1073770512, 1073770513, 1073770514, 1073770515, 1073770516,
})


def _row_matches_values(row: dict[str, Any], values: tuple[float, float, float, float]) -> bool:
    for field, target in zip(GUILD_SKILL_VALUE_FIELDS, values, strict=True):
        val = row.get(field)
        if val is None or not math.isclose(float(val), target, rel_tol=1e-5, abs_tol=1e-6):
            return False
    return True


def patch_guildskilldata_max_rows(rows: list[dict[str, Any]]) -> int:
    """Rewrites Guild Raid skill effect rows (1048577, 1048579..1048582) to max values."""
    seen: set[int] = set()
    to_update: list[tuple[dict[str, Any], tuple[float, float, float, float]]] = []
    for row in rows:
        eid = row.get("_guildSkillEffectId")
        if eid not in GUILD_SKILL_MAX_SPECS:
            continue
        if eid in seen:
            raise ValueError(f"Duplicate guildskilldata effect row: {eid}")
        seen.add(eid)
        stock_vals, patched_vals = GUILD_SKILL_MAX_SPECS[eid]
        if _row_matches_values(row, patched_vals):
            continue
        if not _row_matches_values(row, stock_vals):
            actual = tuple(row.get(f) for f in GUILD_SKILL_VALUE_FIELDS)
            raise ValueError(
                f"Unexpected guildskilldata row {eid}: {actual!r}"
            )
        to_update.append((row, patched_vals))
    if seen != set(GUILD_SKILL_MAX_SPECS):
        missing = sorted(set(GUILD_SKILL_MAX_SPECS) - seen)
        raise ValueError(f"guildskilldata missing effect row(s): {missing}")
    for row, patched_vals in to_update:
        for field, target in zip(GUILD_SKILL_VALUE_FIELDS, patched_vals, strict=True):
            row[field] = target
    return len(to_update)


def inspect_guildskilldata_max_rows(rows: list[dict[str, Any]]) -> tuple[bool, str]:
    """Inspects ``guildskilldata.unity3d`` rows for maxed Guild Raid skill values."""
    found: dict[int, dict[str, Any]] = {}
    for row in rows:
        eid = row.get("_guildSkillEffectId")
        if eid in GUILD_SKILL_MAX_SPECS:
            found[eid] = row
    if len(found) != len(GUILD_SKILL_MAX_SPECS):
        missing = sorted(set(GUILD_SKILL_MAX_SPECS) - set(found))
        return False, f"guildskilldata missing effects {missing}"

    patched_count = 0
    stock_count = 0
    for eid, (stock_vals, patched_vals) in GUILD_SKILL_MAX_SPECS.items():
        row = found[eid]
        if _row_matches_values(row, patched_vals):
            patched_count += 1
        elif _row_matches_values(row, stock_vals):
            stock_count += 1
        else:
            actual = tuple(row.get(f) for f in GUILD_SKILL_VALUE_FIELDS)
            return False, f"Unexpected values on effect {eid}: {actual!r}"

    if patched_count == len(GUILD_SKILL_MAX_SPECS):
        return (
            True,
            "1048577=1M flat dmg, 1048579=100% 1-hit DR, 1048580=100% HP, "
            "1048581=100% MP, 1048582=20 dispels",
        )
    if stock_count == len(GUILD_SKILL_MAX_SPECS):
        return False, "Original Guild Raid skill scaling values (1048577..1048582)"
    return False, f"Partially patched ({patched_count}/{len(GUILD_SKILL_MAX_SPECS)} effects)"


def patch_guildskillinfo_max_rows(rows: list[dict[str, Any]]) -> int:
    """Attaches 100% maxMP restore (effect ``1048581``) to Absolute Protection."""
    for row in rows:
        if row.get("_guildSkillId") != ABSOLUTE_PROTECTION_SKILL_ID:
            continue
        current = (row.get("_effect03Id"), row.get("_effect03Target"))
        if current == ABSOLUTE_PROTECTION_PATCHED_EFFECT3:
            return 0
        if current != ABSOLUTE_PROTECTION_STOCK_EFFECT3:
            raise ValueError(
                f"Unexpected guildskillinfo row {ABSOLUTE_PROTECTION_SKILL_ID} effect03: {current!r}"
            )
        row["_effect03Id"], row["_effect03Target"] = ABSOLUTE_PROTECTION_PATCHED_EFFECT3
        return 1
    raise ValueError(f"guildskillinfo missing skill row {ABSOLUTE_PROTECTION_SKILL_ID}")


def inspect_guildskillinfo_max_rows(rows: list[dict[str, Any]]) -> tuple[bool, str]:
    """Checks whether Absolute Protection carries effect ``1048581`` (allies MP)."""
    for row in rows:
        if row.get("_guildSkillId") != ABSOLUTE_PROTECTION_SKILL_ID:
            continue
        current = (row.get("_effect03Id"), row.get("_effect03Target"))
        if current == ABSOLUTE_PROTECTION_PATCHED_EFFECT3:
            return True, "Absolute Protection effect03=1048581 (100% maxMP)"
        if current == ABSOLUTE_PROTECTION_STOCK_EFFECT3:
            return False, "Original Absolute Protection effect03 (-1, 255)"
        return False, f"Unexpected Absolute Protection effect03: {current!r}"
    return False, f"guildskillinfo missing skill row {ABSOLUTE_PROTECTION_SKILL_ID}"


def patch_monsterdata_boss_car_rows(rows: list[dict[str, Any]]) -> int:
    """Zeros ``_car`` (0.0) on all 70 Guild Raid boss rows in ``monsterdata.unity3d``."""
    seen: set[int] = set()
    to_update: list[dict[str, Any]] = []
    for row in rows:
        mid = row.get("_monsterId")
        if mid not in GUILD_RAID_BOSS_MONSTER_IDS:
            continue
        if mid in seen:
            raise ValueError(f"Duplicate monsterdata Guild Raid boss row: {mid}")
        seen.add(mid)
        car = float(row.get("_car", -999.0))
        if math.isclose(car, 0.0, abs_tol=1e-6):
            continue
        if not math.isclose(car, -1.0, abs_tol=1e-5):
            raise ValueError(
                f"Unexpected monsterdata _car={car!r} for Guild Raid boss {mid}"
            )
        to_update.append(row)
    if seen != GUILD_RAID_BOSS_MONSTER_IDS:
        missing = len(GUILD_RAID_BOSS_MONSTER_IDS - seen)
        raise ValueError(f"monsterdata missing {missing} Guild Raid boss row(s)")
    for row in to_update:
        row["_car"] = 0.0
    return len(to_update)


def inspect_monsterdata_boss_car_rows(rows: list[dict[str, Any]]) -> tuple[bool, str]:
    """Inspects ``monsterdata.unity3d`` Guild Raid boss counterattack rates."""
    cars: list[float] = []
    for row in rows:
        if row.get("_monsterId") in GUILD_RAID_BOSS_MONSTER_IDS:
            cars.append(float(row.get("_car", -999.0)))
    total = len(GUILD_RAID_BOSS_MONSTER_IDS)
    if len(cars) != total:
        return False, f"Found {len(cars)}/{total} Guild Raid boss rows in monsterdata"
    zero_count = sum(1 for v in cars if math.isclose(v, 0.0, abs_tol=1e-6))
    stock_count = sum(1 for v in cars if math.isclose(v, -1.0, abs_tol=1e-5))
    if zero_count == total:
        return True, f"All {total} Guild Raid boss rows set to _car=0.0 (0% counter rate)"
    if stock_count == total:
        return False, f"Original _car=-1.0 across all {total} Guild Raid boss rows (300 / 3%)"
    return False, f"Partially patched ({zero_count}/{total} at _car=0.0, {stock_count} stock)"
