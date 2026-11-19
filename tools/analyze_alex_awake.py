"""Read-only reference-table audit for the experimental Alex Awakening.

Run as ``python -m tools.analyze_alex_awake --resources <fwt_resources_v1.zip>``.
This research utility does not produce or apply a game patch.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import struct
import zipfile
from pathlib import Path
from typing import Any

import UnityPy
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection

from core.apk_tooling import _decrypt_datatable, _encrypt_datatable
from core.core_patches import REFERENCE_SO_SHA256

_ALEX_FIVE = 0x130185
_ALEX_SIX = 0x130186
_CANDIDATE_SKILL = 0x100185


def _rows(archive: zipfile.ZipFile, name: str) -> list[dict[str, Any]]:
    path = f"files/Resources/datatable/{name}.unity3d"
    clear, _, _ = _decrypt_datatable(archive.read(path))
    result: list[dict[str, Any]] = []
    for obj in UnityPy.load(clear).objects:
        if obj.type.name == "MonoBehaviour":
            result.extend(obj.read_typetree().get("_data") or [])
    if not result:
        raise ValueError(f"No rows found in {path}")
    return result


def analyze(resources: Path) -> dict[str, Any]:
    """Report candidate IDs, Alex's evolution gap and Guild Raid boss flags."""
    with zipfile.ZipFile(resources) as archive:
        creatures = _rows(archive, "creaturedataenglish")
        rebirth = _rows(archive, "creaturerebirth")
        skills = _rows(archive, "skilldataenglish")
        skill_levels = _rows(archive, "skillleveltable")
        skill_fx = _rows(archive, "skillfxdata")
        monsters = _rows(archive, "monsterdata")
        raid = _rows(archive, "guildraidbosstable")
        skill_locales: dict[str, dict[str, int]] = {}
        for path in archive.namelist():
            match = re.fullmatch(r"files/Resources/datatable/(skilldata[a-z]*)\.unity3d", path)
            if match is None:
                continue
            name = match.group(1)
            rows = skills if name == "skilldataenglish" else _rows(archive, name)
            skill_locales[name] = {
                "rows": len(rows),
                "candidate_matches": sum(row.get("_skillId") == _CANDIDATE_SKILL
                                         for row in rows),
            }

    hero_rows = [r for r in creatures if r.get("_creatureId") in (_ALEX_FIVE, _ALEX_SIX)]
    if len(hero_rows) != 2 or any(r.get("_name") != "Alex" for r in hero_rows):
        raise ValueError("Unexpected Alex creature records")
    candidates = sum(
        1 for rows in (skills, skill_levels, skill_fx)
        for row in rows if row.get("_skillId") == _CANDIDATE_SKILL
    )
    monster_by_id = {row["_monsterId"]: row for row in monsters}
    boss_flags = [monster_by_id[row["_monsterId"]]["_boss"] for row in raid]
    fx = [row for row in skill_fx if row.get("_creatureId") == _ALEX_FIVE
          and row.get("_skillNo") == 2]
    if len(fx) != 1:
        raise ValueError("Unexpected Giga-break effect records")
    return {
        "alex": [
            {"id": row["_creatureId"], "model": row["_graphicPrefeb"],
             "awake_skill": row["_skill4"]}
            for row in hero_rows
        ],
        "alex_five_star_rebirth_rules": [
            row for row in rebirth if row.get("_creatureId") == _ALEX_FIVE
        ],
        "candidate_skill_id": _CANDIDATE_SKILL,
        "candidate_matches_in_three_tables": candidates,
        "localized_skill_tables": skill_locales,
        "guild_raid_boss_rows": len(boss_flags),
        "guild_raid_boss_flags": sorted(set(boss_flags)),
        "monster_boss_type_counts": {str(kind): sum(row.get("_boss") == kind
                                                       for row in monsters)
                                     for kind in (80, 90, 100)},
        "giga_break": {key: fx[0][key] for key in (
            "_skillId", "_skillNo", "_castFxPrefeb", "_finishSound0", "_damagedFrame0"
        )},
    }


def probe_roundtrip(resources: Path) -> dict[str, int]:
    """Exercise experimental Unity table shape entirely in memory.

    The cloned skill, costs and effects are placeholders. They are not a
    working design and this function never emits a modified asset or APK.
    """
    result: dict[str, int] = {}
    names = ("creaturerebirth", "creaturedataenglish", "skilldataenglish",
             "skillleveltable", "skillfxdata")
    with zipfile.ZipFile(resources) as archive:
        for name in names:
            path = f"files/Resources/datatable/{name}.unity3d"
            clear, key, iv = _decrypt_datatable(archive.read(path))
            env = UnityPy.load(clear)
            objects = [obj for obj in env.objects if obj.type.name == "MonoBehaviour"]
            if len(objects) != 1:
                raise ValueError(f"Unexpected MonoBehaviour count in {path}")
            obj = objects[0]
            tree = obj.read_typetree()
            rows = tree.get("_data") or []
            if name == "creaturerebirth":
                if any(row.get("_creatureId") == _ALEX_FIVE for row in rows):
                    raise ValueError("Alex already has a five-star evolution rule")
                donor = next(row for row in rows if row.get("_creatureId") == 1249317
                             and row.get("_grade") == 5)
                row = copy.deepcopy(donor)
                row.update(_creatureId=_ALEX_FIVE, _creatureId2=_ALEX_SIX)
                rows.append(row)
            elif name == "creaturedataenglish":
                row = next(row for row in rows if row.get("_creatureId") == _ALEX_SIX)
                if row.get("_skill4") != -1:
                    raise ValueError("Unexpected Alex six-star skill")
                row["_skill4"] = _CANDIDATE_SKILL
            else:
                if any(row.get("_skillId") == _CANDIDATE_SKILL for row in rows):
                    raise ValueError(f"Candidate skill ID already exists in {name}")
                if name == "skillfxdata":
                    donor = next(row for row in rows if row.get("_creatureId") == _ALEX_FIVE
                                 and row.get("_skillNo") == 2)
                    row = copy.deepcopy(donor)
                    row.update(_creatureId=_ALEX_SIX, _skillNo=3)
                else:
                    donor = next(row for row in rows if row.get("_skillId") == 1049717)
                    row = copy.deepcopy(donor)
                    if name == "skilldataenglish":
                        row["_cooltime"] = 1
                row["_skillId"] = _CANDIDATE_SKILL
                rows.append(row)
            obj.save_typetree(tree)
            encoded = _encrypt_datatable(bytes(getattr(env.file, "save")()), key, iv)  # noqa: B009
            decoded, _, _ = _decrypt_datatable(encoded)
            decoded_rows = [r for entry in UnityPy.load(decoded).objects
                            if entry.type.name == "MonoBehaviour"
                            for r in (entry.read_typetree().get("_data") or [])]
            if name == "creaturerebirth":
                found = [r for r in decoded_rows if r.get("_creatureId") == _ALEX_FIVE
                         and r.get("_creatureId2") == _ALEX_SIX and r.get("_grade") == 5]
            elif name == "creaturedataenglish":
                found = [r for r in decoded_rows if r.get("_creatureId") == _ALEX_SIX
                         and r.get("_skill4") == _CANDIDATE_SKILL]
            else:
                found = [r for r in decoded_rows if r.get("_skillId") == _CANDIDATE_SKILL]
            if len(found) != 1:
                raise ValueError(f"Round-trip failed for {name}")
            result[name] = len(decoded_rows)
    return result


def audit_animation(resources: Path, *, probe: bool = False) -> dict[str, Any]:
    """List animation clips and serialized template keys without modifying assets."""
    with zipfile.ZipFile(resources) as archive:
        bundle = archive.read("files/Resources/character/player/paladin.unity3d")
    clips: list[str] = []
    candidates: list[dict[str, Any]] = []
    env = UnityPy.load(bundle)
    objects = list(env.objects)
    game_objects = {obj.path_id: obj.read().m_Name for obj in objects
                    if obj.type.name == "GameObject"}
    for obj in objects:
        if obj.type.name == "AnimationClip":
            clips.append(obj.read().m_Name)
        elif obj.type.name == "MonoBehaviour":
            try:
                tree = obj.read_typetree()
            except (ValueError, TypeError, NotImplementedError):
                continue
            keys = [key for key in tree if "anim" in key.lower()]
            if keys:
                game_object = tree.get("m_GameObject") or {}
                object_name = game_objects.get(int(game_object.get("m_PathID", 0)))
                candidates.append({"name": tree.get("m_Name", ""), "keys": keys,
                                   "game_object": object_name,
                                   "animation_names": tree.get("_animationNames")})
                if probe and object_name == "Paladin_05":
                    names = tree["_animationNames"]
                    if len(names) != 16 or names[3] != "Paladin_Skill2":
                        raise ValueError("Unexpected Paladin animation mapping")
                    tree["_animationNames"] = [*names, "Paladin_Skill2"]
                    obj.save_typetree(tree)
    report: dict[str, Any] = {"clips": sorted(clips), "animation_component_keys": candidates}
    if probe:
        encoded = bytes(getattr(env.file, "save")())  # noqa: B009
        saved = list(UnityPy.load(encoded).objects)
        saved_game_objects = {obj.path_id: obj.read().m_Name for obj in saved
                              if obj.type.name == "GameObject"}
        saved_mappings: dict[str, list[str]] = {}
        for obj in saved:
            if obj.type.name != "MonoBehaviour":
                continue
            try:
                tree = obj.read_typetree()
            except (ValueError, TypeError, NotImplementedError):
                continue
            game_object = tree.get("m_GameObject") or {}
            object_name = saved_game_objects.get(int(game_object.get("m_PathID", 0)))
            names = tree.get("_animationNames")
            if object_name is not None and names is not None:
                if object_name in saved_mappings:
                    raise ValueError("Duplicate animation mapping on a prefab")
                saved_mappings[object_name] = names
        expected = {row["game_object"]: row["animation_names"] for row in candidates}
        if "Paladin_05" not in expected or len(expected) != len(candidates):
            raise ValueError("Ambiguous original animation mapping")
        expected["Paladin_05"] = [*expected["Paladin_05"], "Paladin_Skill2"]
        if saved_mappings != expected:
            raise ValueError("Animation alias did not survive the in-memory round-trip")
        report["in_memory_alias_roundtrip"] = True
    return report


def analyze_server(server: Path) -> dict[str, Any]:
    """Audit reference rule pointers and adjacent relocations without mutation."""
    if hashlib.sha256(server.read_bytes()).hexdigest() != REFERENCE_SO_SHA256:
        raise ValueError("Server is not the supported original reference SO")
    with server.open("rb") as stream:
        elf = ELFFile(stream)
        segments = list(elf.iter_segments())
        symtab = elf.get_section_by_name(".symtab")
        if not isinstance(symtab, SymbolTableSection):
            raise ValueError("Reference server symbol table not found")
        rules = [sym for sym in symtab.iter_symbols() if sym.name == "_ZL16kFwtRebirthRules"]
        if len(rules) != 1:
            raise ValueError("Reference evolution rule table not found uniquely")
        start = int(rules[0]["st_value"])
        size = int(rules[0]["st_size"])
        if size % 56:
            raise ValueError("Unexpected evolution rule size")

        def read_vaddr(address: int, size: int) -> bytes:
            for segment in segments:
                if (segment["p_type"] == "PT_LOAD"
                        and segment["p_vaddr"] <= address
                        and address + size <= segment["p_vaddr"] + segment["p_filesz"]):
                    stream.seek(segment["p_offset"] + address - segment["p_vaddr"])
                    return stream.read(size)
            raise ValueError(f"Address outside file-backed PT_LOAD: {address:#x}")

        relocations: dict[int, int] = {}
        for section in elf.iter_sections():
            if isinstance(section, RelocationSection) and section.header.sh_type == "SHT_RELA":
                for relocation in section.iter_relocations():
                    relocations[int(relocation["r_offset"])] = int(relocation["r_addend"])
        alex_rules: list[dict[str, str | int]] = []
        donor_rules: list[dict[str, str | int]] = []
        for address in range(start, start + size, 56):
            source_ptr = relocations.get(address)
            target_ptr = relocations.get(address + 8)
            if source_ptr is None or target_ptr is None:
                raise ValueError(f"Missing evolution pointer relocation at {address:#x}")
            source = read_vaddr(source_ptr, 9).split(b"\0", 1)[0].decode("ascii")
            if source not in ("00130184", "00130185", "00131025"):
                continue
            target = read_vaddr(target_ptr, 9).split(b"\0", 1)[0].decode("ascii")
            grade, level = struct.unpack("<II", read_vaddr(address + 16, 8))
            row = {"source": source, "target": target, "grade": grade,
                   "level": level, "address": hex(address)}
            (donor_rules if source == "00131025" else alex_rules).append(row)
        relro = any(seg["p_type"] == "PT_GNU_RELRO"
                    and seg["p_vaddr"] <= start
                    and start + size <= seg["p_vaddr"] + seg["p_memsz"] for seg in segments)
        end = start + size
        cost_symbols = [sym for sym in symtab.iter_symbols()
                        if sym.name == "_ZL22kFwtSkillLevelCostRows"]
        cost_audit: dict[str, Any] = {}
        if len(cost_symbols) == 1:
            cost_start = int(cost_symbols[0]["st_value"])
            cost_bytes = read_vaddr(cost_start, int(cost_symbols[0]["st_size"]))
            for identifier in (1048965, 1049717):
                needle = struct.pack("<I", identifier)
                positions = [index for index in range(len(cost_bytes) - 3)
                             if cost_bytes[index:index + 4] == needle]
                cost_audit[str(identifier)] = [
                    {"offset": offset, "bytes": cost_bytes[offset:offset + 32].hex()}
                    for offset in positions
                ]
        creature_skill_symbols = [sym for sym in symtab.iter_symbols()
                                  if sym.name == "_ZL21kFwtCreatureSkillRows"]
        creature_skill_audit: dict[str, Any] = {}
        if len(creature_skill_symbols) == 1:
            skill_start = int(creature_skill_symbols[0]["st_value"])
            skill_size = int(creature_skill_symbols[0]["st_size"])
            skill_bytes = read_vaddr(skill_start, skill_size)
            for identifier in (_ALEX_FIVE, _ALEX_SIX):
                needle = struct.pack("<I", identifier)
                offsets = [index for index in range(len(skill_bytes) - 3)
                           if skill_bytes[index:index + 4] == needle]
                creature_skill_audit[str(identifier)] = [
                    {"address": hex(skill_start + offset),
                     "bytes": skill_bytes[offset:offset + 24].hex()} for offset in offsets
                ]
        # Merely report the ELF layout; zero-fill space is not automatically a
        # safe cave and no program header or file content is changed here.
        loads = [seg for seg in segments if seg["p_type"] == "PT_LOAD"]
        writable = [seg for seg in loads if int(seg["p_flags"]) & 2]
        last = max(writable, key=lambda seg: int(seg["p_vaddr"]) + int(seg["p_memsz"]))
        memory_end = int(last["p_vaddr"]) + int(last["p_memsz"])
        alignment = int(last["p_align"])
        next_page = (memory_end + alignment - 1) // alignment * alignment
        later_loads = [int(seg["p_vaddr"]) for seg in loads
                       if int(seg["p_vaddr"]) >= memory_end]
        later_alloc_sections = [int(section["sh_addr"]) for section in elf.iter_sections()
                                if int(section["sh_flags"]) & 2
                                and int(section["sh_size"]) > 0
                                and int(section["sh_addr"]) >= memory_end]
        next_relocations = [address for address in relocations if address >= memory_end]
        extension = {"segment_end": hex(memory_end), "alignment": alignment,
                     "next_aligned_boundary": hex(next_page),
                     "bytes_to_boundary": next_page - memory_end,
                     "next_load": hex(min(later_loads)) if later_loads else None,
                     "next_allocated_section": (hex(min(later_alloc_sections))
                                                if later_alloc_sections else None),
                     "next_relocation": (hex(min(next_relocations))
                                         if next_relocations else None)}
        return {"rules": size // 56, "start": hex(start), "end": hex(end),
                "relro": relro, "alex_rules": alex_rules, "test_donor_rules": donor_rules,
                "candidate_code_region_sha256": hashlib.sha256(
                    read_vaddr(0xB34D44, 196)).hexdigest(),
                "lookup_miss_instruction": read_vaddr(0x9029B8, 4).hex(),
                "skill_recognition_instruction": read_vaddr(0x8C39D0, 4).hex(),
                "skill_cost_miss_instruction": read_vaddr(0x800E00, 4).hex(),
                "skill_cave_sha256": hashlib.sha256(read_vaddr(0xB34E08, 92)).hexdigest(),
                "skill_cost_id_occurrences": cost_audit,
                "alex_creature_skill_id_occurrences": creature_skill_audit,
                "test_donor_tail_relocations": [hex(addr) for addr in sorted(relocations)
                                                if 0xBA6DD0 <= addr < 0xBA6DF8],
                "following_256_bytes_relocations": sum(end <= addr < end + 256
                                                       for addr in relocations),
                "writable_segment_extension_candidate": extension}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--resources", required=True, type=Path, help="Original resource ZIP")
    parser.add_argument("--probe-roundtrip", action="store_true",
                        help="Exercise placeholder table edits in memory only")
    parser.add_argument("--server", type=Path, help="Optional original server SO to audit")
    parser.add_argument("--animation", action="store_true", help="Inspect Paladin animation data")
    parser.add_argument("--probe-animation", action="store_true",
                        help="Test a Paladin Awake animation alias in memory only")
    parser.add_argument("--cooldown-effects", action="store_true",
                        help="Inspect reference CoolTimeReduce effect records")
    parser.add_argument("--skill-examples", action="store_true",
                        help="Inspect original Alex and Persona skill records")
    parser.add_argument("--effect-id-audit", action="store_true",
                        help="Check two candidate effect IDs in localized effect tables")
    parser.add_argument("--cooldown-links", action="store_true",
                        help="Find direct table links to cooldown-reduction effects")
    parser.add_argument("--all-range", action="store_true",
                        help="Summarize skills with the candidate all-map range type")
    args = parser.parse_args()
    report = analyze(args.resources)
    if args.probe_roundtrip:
        report["placeholder_roundtrip_rows"] = probe_roundtrip(args.resources)
    if args.server:
        report["server"] = analyze_server(args.server)
    if args.animation or args.probe_animation:
        report["paladin_animation"] = audit_animation(args.resources, probe=args.probe_animation)
    if args.cooldown_effects:
        with zipfile.ZipFile(args.resources) as archive:
            effects = _rows(archive, "skilleffecttableenglish")
        report["cooldown_effect_keys"] = list(effects[0]) if effects else []
        report["cooldown_effects"] = [row for row in effects if any(
            "type" in key.lower() and value == 186 for key, value in row.items()
        )]
    if args.skill_examples:
        with zipfile.ZipFile(args.resources) as archive:
            skills = _rows(archive, "skilldataenglish")
            effects = _rows(archive, "skilleffecttableenglish")
            levels = _rows(archive, "skillleveltable")
        report["skill_examples"] = [row for row in skills
                                    if row.get("_skillId") in (1048964, 1049715, 1049717)]
        effect_ids = {21172225, 16847920, 0x10018501, 0x10018502}
        report["effect_examples"] = [row for row in effects
                                     if row.get("_skillEffectId") in effect_ids]
        report["skill_level_examples"] = [row for row in levels
                                          if row.get("_skillId") in (1048964, 1049717)]
        report["fixed_damage_users"] = [{key: row.get(key) for key in
                                         ("_skillId", "_skillName", "_effect01", "_effect02",
                                          "_effect03", "_effect04", "_tooltip")}
                                        for row in skills if any(
                                            row.get(f"_effect{index:02d}") == 16847920
                                            for index in range(1, 5)
                                        )][:12]
    if args.effect_id_audit:
        matches: dict[str, dict[str, int]] = {}
        with zipfile.ZipFile(args.resources) as archive:
            for path in archive.namelist():
                found = re.fullmatch(
                    r"files/Resources/datatable/(skilleffecttable[a-z]*)\.unity3d", path
                )
                if found is None:
                    continue
                rows = _rows(archive, found.group(1))
                matches[found.group(1)] = {
                    hex(identifier): sum(row.get("_skillEffectId") == identifier for row in rows)
                    for identifier in (0x10018501, 0x10018502)
                }
        report["candidate_effect_ids_by_locale"] = matches
    if args.cooldown_links:
        with zipfile.ZipFile(args.resources) as archive:
            effects = _rows(archive, "skilleffecttableenglish")
            skills = _rows(archive, "skilldataenglish")
            sets = _rows(archive, "setitemtableenglish")
            bonuses = _rows(archive, "equipsetbonustable")
        effect_ids = {row["_skillEffectId"] for row in effects if row.get("_skillEffectType") == 186}
        linked_skills = [row for row in skills if any(
            row.get(f"_effect{index:02d}") in effect_ids for index in range(1, 5)
        )]
        linked_ids = effect_ids | {row["_skillId"] for row in linked_skills}
        report["cooldown_direct_links"] = {
            "effect_ids": sorted(effect_ids),
            "skills": [{key: value for key, value in row.items()
                        if key in ("_skillId", "_skillName", "_effect01", "_effect02",
                                   "_effect03", "_effect04")} for row in linked_skills],
            "set_rows": [row for row in sets if any(value in linked_ids for value in row.values()
                                                      if isinstance(value, int))],
            "unrestricted_sets": [row for row in sets
                                  if row.get("_setPreconditionid") == -1
                                  and any(value in linked_ids for value in row.values()
                                          if isinstance(value, int))],
            "equipment_bonus_rows": [row for row in bonuses if any(
                value in linked_ids for value in row.values() if isinstance(value, int)
            )],
        }
    if args.all_range:
        with zipfile.ZipFile(args.resources) as archive:
            skills = _rows(archive, "skilldataenglish")
        full_range = [row for row in skills if row.get("_skillRangeType") == 2]
        report["all_range_candidates"] = {
            "count": len(full_range),
            "ranges": sorted({row.get("_range") for row in full_range}),
            "examples": [{key: row.get(key) for key in (
                "_skillId", "_skillName", "_range", "_skillRangeType", "_skillTarget",
                "_skillEffectRange", "_skillEffectRangeType", "_useParameterKind")}
                for row in full_range[:12]],
            "enemy_awake_examples": [{key: row.get(key) for key in (
                "_skillId", "_skillName", "_range", "_skillRangeType", "_skillTarget",
                "_skillEffectRange", "_skillEffectRangeType", "_useParameterKind")}
                for row in full_range if row.get("_skillTarget") == 1
                and row.get("_useParameterKind") == 5][:12],
        }
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
