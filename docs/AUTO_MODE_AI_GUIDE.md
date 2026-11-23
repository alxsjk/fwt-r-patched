# Auto-Battle AI Modification Specification & Reference Guide

This document defines the architecture, verified client (`libil2cpp.so`) addresses, struct layouts, isolation invariants, and implementation workflow for modifying **Auto Mode** hero targeting and skill-selection behavior in `fwt_0.682_offline_v1574.apk`, using **Merlin Slot-1 Auto Support** ([core/merlin_auto_support.py](../core/merlin_auto_support.py), Feature `14.01` `--merlin-auto-support`) as the reference implementation.

Because Auto Mode logic lives inside the encrypted client binary (`libil2cpp.so`), custom AI rules are delivered via **post-Covault native trampolines** from dead code caves in `libfwt_local_server.so` using `PATCH_IL2CPP_HELPER` (`0xAB575C`) once AppSealing unpacks `libil2cpp.so` at boot (`IL2CPP_BASE_CACHE` at `0xBE3798`).

---

## 1. Stock Auto Mode Decision Pipeline (`libil2cpp.so`)

During a unit's Auto Mode turn, skill and target resolution follows this exact call graph:

1. **Descending skill scan (`4 -> 0`)**:
   - `PlayerAI::NormalStateFindTakeSkillTarget` (`0x18EA7F0`) iterates `skillIndex` downward from `skillLastIndex` (`[playerAI + 0x7c]`, usually `4` = Awake) to `skillFirstIndex` (`[playerAI + 0x80]`, usually `0`).
   - For each index, it checks `CharactersAI::IsEnableUsingSkill` (`0x1A36BA8`: cooldown/MP/CC/auto-toggle) and dispatches `vtable[0x340]` → `PlayerAI::EnableUseSkillToTarget` (`0x18EAF58`).
   - *Implication*: If a hero's support skill lives at a lower index (e.g., `_skill1`) than an offensive skill at `_skill2`, the stock loop tests the attack at `_skill2` first unless skill priority is explicitly reordered or overridden for that hero.
2. **Support before attack**:
   - `PlayerAI::EnableUseSkillToTarget` (`0x18EAF58`) first runs `AIStatePhaseFindSupport` (`0x20ECE08`, or `AIStatePhaseFindSupportInPlace` `0x20F16B0` when immobilized) via `AIStatePhaseFindSupport::Execute` (`0x20ED040`).
   - If support targeting returns false (`[state + 0x18] == 0`), control falls back to `AIStatePhaseFindAttackPlayer` (`0x2187A70`) to attack an enemy or reposition.
3. **Why stock Auto Mode ignores non-heal support skills**:
   - `AIStatePhaseFindSupport::IsEnableToUseSupportSkill` (`0x20EE340`) checks:
     1. `SkillContainer::IsSkillSelectableInAuto` (`0x20245F8`), `IsSkillSelectable` (`0x2024768`), `SelectSkill` (`0x20247D0`), and caches `Skill*` at `[state + 0x38]`.
     2. `Skill::GetSupportSkill` (`0x1B71910`) → caches `uint8 supportSkillType` at `[state + 0x40]`. Non-heal buffs and Awakening cooldown skills (such as Merlin's *Magic infusion*, `_skill2 = 1053188`) return **`0`**.
     3. `AIStatePhaseFindSupport::IsEnableSupportSkill` (`0x20ED830`): checks `Skill::IsCastable` (`0x1B6F57C`) and `SkillBase::IsTargetTypeAlly` (`0x1B74CD0`: `_skillTarget` in `{0, 2, 3}`).
     4. `AIStatePhaseFindSupport::IsTakenEffectedMember` (`0x20ED88C`) loops `Camp._members` calling `vtable[0x210]` (`IsUseSupportSkillState`).
   - In **`AIStatePhaseFindSupport::IsUseSupportSkillState` (`0x20EDBCC`)** (and `InPlace` **`0x20F1AF0`**):
     - `supportSkillType == 1`: HP heal — allowed only when `hp / maxHp <= threshold` (`[0x2E60608]`).
     - `supportSkillType == 10` (`0xa`): MP heal — allowed only when `mp / maxMp <= threshold`.
     - `supportSkillType == 5`: checks `StatusEffectContainer::HasStatusEffect` (`0x1990F98`).
     - `supportSkillType == 0` or `11` (`0xb`): calls `StatusEffectContainer::HasEqualBuffEffectId(ally.effects, skill)` (`0x1990D54`), which returns `0` when an ally has no active buff/effect yet — causing `IsUseSupportSkillState` to return **`0`**. Consequently `IsTakenEffectedMember` finds 0 qualifying allies and the hero attacks enemies instead.
4. **Candidate evaluation & tie-breaking**:
   - When `IsTakenEffectedMember` approves at least one ally, `AIStatePhaseFindSupport::SupportFindTarget` (`0x20ED150`) iterates all walkable tiles (`0x1A35BD0`), verifies `IsProperSkillTargetType` (`0x1B71200`), re-calls `IsUseSupportSkillState`, and ranks `(moveTile, targetAlly)` candidates via `AIStatePhaseFindSupport::CompareFindTargetStep` (`0x20EEDB4`; `InPlace` `0x20F31C0`).
   - If the best candidate list `[state + 0x58]` / `[state + 0x50]` remains empty (`count == 0`) because no approved ally is within movement + skill range, `SupportFindTarget` returns **`0`** and Auto Mode cleanly falls back to attacking enemies.
   - When `CompareFindTargetStep` compares two candidates (`bestInfo` already populated, `bestCount > 0`), the midpoint at **`+0x178`** (`0x20EEF2C` / `0x20F3338`) decides whether to overwrite (`accept = site + 0x40`), preserve existing best (`reject = site + 0x64`), or continue into distance tie-breaking (`site + 0x10`).

---

## 2. Verified `libil2cpp.so` RVAs & Field Offsets (Client `0.682`)

> **Always resolve static/runtime inspection against decrypted memory pages.** On disk `libil2cpp.so` `.text` is AppSealed; use emulator runtime dumps under gitignored `output/unpacked_ref/` for verification.

### 2.1 AI & Support Selection RVAs

| Symbol | RVA | Notes |
| --- | --- | --- |
| `PlayerAI::get_IsPvpPlayer` | `0x18EA6B4` | `ldrb w0, [x0, #0x84]` |
| `PlayerAI::NormalStateFindTakeSkillTarget` | `0x18EA7F0` | Skill loop `4 -> 0` at `0x18EA850` |
| `PlayerAI::EnableUseSkillToTarget` | `0x18EAF58` | Runs support phase then attack phase |
| `CharactersAI::IsEnableUsingSkill` | `0x1A36BA8` | Skill castability + auto gate |
| `CharactersAI::SetMoveTileSkillAIState` | `0x1A36370` | Commits chosen `(moveTile, targetTile, skillIdx)` |
| `SkillContainer::IsSkillSelectableInAuto` | `0x20245F8` | Checks active skill & player auto-skill toggle |
| `Skill::GetSupportSkill` | `0x1B71910` | Returns `1` (HP heal), `5`, `10` (MP heal), or `0` |
| `Skill::IsCastable` | `0x1B6F57C` | Cooldown, MP, silence/CC gates |
| `Skill::ResetRemainCoolTime` | `0x1B718E0` | `str wzr, [x0, #0x30]; ret` — `[Skill + 0x30]` is the elapsed counter |
| `Skill::GetCurrentCoolTime` | `0x16064B4` | True remaining cooldown from `_cooltime - [Skill+0x30] + adjustments` |
| Awake-cooldown wrapper | `0x1606428` | `IsAwakeningSkill(skill) ? GetCurrentCoolTime(skill) : -1` (**called by 14.01**) |
| `SkillBase::IsTargetTypeAlly` | `0x1B74CD0` | True when `skillData._skillTarget` in `{0, 2, 3}` |
| `Skill::IsProperSkillTargetType` | `0x1B71200` | Enforces target kind & status constraints |
| `AIStatePhaseFindSupport::SupportFindTarget` | `0x20ED150` | Evaluates walkable tiles & best target |
| `AIStatePhaseFindSupport::SearchingManyTargetsCenterOfFindTarget` | `0x20ED47C` | Maximizes hit count for AoE skills (`gt` only) |
| `AIStatePhaseFindSupport::IsEnableSupportSkill` | `0x20ED830` | `IsCastable && IsTargetTypeAlly` |
| `AIStatePhaseFindSupport::IsTakenEffectedMember` | `0x20ED88C` | Iterates `Camp._members` |
| `AIStatePhaseFindSupport::IsUseSupportSkillState` | `0x20EDBCC` | Per-ally eligibility predicate (**hooked by 14.01**) |
| `AIStatePhaseFindSupport::IsEnableToUseSupportSkill` | `0x20EE340` | Pre-check before `Execute()` |
| `AIStatePhaseFindSupport::CompareFindTargetStep` | `0x20EEDB4` | Mid-hook `+0x178` at `0x20EEF2C` (**hooked by 14.01**) |
| `AIStatePhaseFindSupportInPlace::IsUseSupportSkillState` | `0x20F1AF0` | Immobilized variant (**hooked by 14.01**) |
| `AIStatePhaseFindSupportInPlace::CompareFindTargetStep` | `0x20F31C0` | Mid-hook `+0x178` at `0x20F3338` (**hooked by 14.01**) |
| `AISlectTargetWithSkill::SetupTargetSupportDataInfo` | `0x217CF84` | Writes `AISlectTargetWithSkill` fields |
| `GameStage::InitPlayerSpawnPlacement` | `0x1658FE0` | Places `GameStage.get_playerCamp[0..Count-1]` |
| `Camp::OnDeadMember` | `0x1AEE90C` | Retains dead members in `Camp._members` |

### 2.2 Verified Struct Offsets

- **`AIStatePhaseFindSupport` / `AIStatePhaseFindSupportInPlace`**:
  - `+0x18` (`uint8`): `isExecuted`
  - `+0x20` (`Character*` / `Player*`): caster
  - `+0x28` (`PlayerAI*`): owning AI controller
  - `+0x30` (`int32`): `skillIdx`
  - `+0x38` (`Skill*`): selected skill instance
  - `+0x40` (`uint8`): `supportSkillType` from `Skill::GetSupportSkill`
  - `+0x50` / `+0x58` (`AISlectTargetWithSkill*`): best candidate record (`AISlectTargetWithSkill::SetupTargetSupportDataInfo` writes `targetChar` at `+0x10`, `moveTile` at `+0x18`, `skillIdx` at `+0x24`, `count` at `+0x28`, `hpRate` at `+0x38`, `hp` at `+0x3c`)
- **`Character` / `Player` (`Player` subclasses `Character`)**:
  - `+0x18` (`uint8`): `_characterType` (`0` = player hero, `1` = monster, `6` = mercenary)
  - `+0x20` (`CreatureData*`): creature template (`+0x10` `int32 _creatureId`, `+0x28` `uint8 _combatType`: `1` Defense/Tanker, `2` Area, `3` Attack, `4` Balance, `5` Support)
  - `+0x40` (`SkillContainer*`): `+0x18` → `Skill*[]` (`+0x18` `int32 Length`, `+0x20 + i*8` elements)
  - `+0x78` (`Camp*`): owning camp
  - `+0x11a` (`uint8`): `_isDead` (`0` = alive, non-zero = dead)
  - `+0x1c0` (`uint8`, `Player` only — check `_characterType == 0` first!): `_isAutoPlay` (`!= 0` in Auto Mode)
- **`Camp`**:
  - `+0x18` (`uint8`): `_campType` (`0` = PlayerCamp; non-zero = Opponent / System / MapObj)
  - `+0x20` (`List<Character>*`): `_members` (`+0x10` → backing `Character*[]`, `+0x18` → `int32 _size`)
- **`Skill` / `SkillData`**:
  - `Skill + 0x10` (`Character*`): caster owner
  - `Skill + 0x18` (`SkillData*`): template data (`+0x10` `int32 _skillId`, `+0x28` `uint8 _skillType` [`0` Passive, `1` Active], `+0x29` `uint8 _skillTarget` [`0` Self, `1` Enemy, `2` Ally, `3` All Allies], `+0x4d` `uint8` Awakening flag where `(byte | 1) == 5` iff `get_IsAwakeningSkill == true` at `0x2026950`)
  - `Skill + 0x30` (`int32`): turns-**elapsed** charge counter, NOT the remaining cooldown — `Skill::ResetRemainCoolTime` (`0x1B718E0`) stores `0` there and it counts up per turn. The true remaining cooldown comes from `Skill::GetCurrentCoolTime` (`0x16064B4`, or the Awakening wrapper `0x1606428` which returns `-1` for non-Awakening skills): `max(0, SkillData._cooltime (byte +0x4c) - [Skill+0x30] + buff/stage/Lord-rule adjustments)`.

---

## 3. Non-Negotiable Isolation Invariants

Every future Auto Mode rule **MUST** enforce all of the following guards before deviating from stock behavior:

1. **Preserve Stock Healing**: Unless a feature explicitly requests changing healing thresholds, never modify `supportSkillType == 1` (HP heal) or `supportSkillType == 10` (MP heal) logic.
2. **PlayerCamp + Player Unit + Auto Mode Only**:
   - Require `Character._characterType == 0`, `Camp._campType == 0`, and `Player._isAutoPlay != 0`.
   - This guarantees enemy units, monsters, mercenaries (`6`), manual play, and PvP defense teams (`_campType != 0`) are **never** altered.
3. **Slot-1 Scoped Rules**:
   - When a behavior is scoped to **Slot 1**, verify `Camp._members._items[0] == caster` (`_size >= 1`). Because `Camp::OnDeadMember` (`0x1AEE90C`) does not remove fallen allies from `Camp._members`, index `0` remains fixed throughout battle without requiring extra scratch RAM.
4. **Never Mutate Shared Hero AI Unintentionally**:
   - Dispatch on exact `_skillId` (e.g., `1053188` for Merlin's *Magic infusion*) and/or verified `_creatureId` list (`_creatureId >> 20 == 1` player hero IDs, checking all rarity + Awakened variants), falling back to replaying the exact 4 displaced instructions whenever any check does not match.

---

## 4. Reference Implementation: Merlin Slot-1 (`14.01`)

`core/merlin_auto_support.py` (`--merlin-auto-support`, Feature `14.01`) provides the template architecture:

- **Host Hook (`libfwt_local_server.so`)**: `0xAB3300` (`stlrb w8, [x9]` → `bl 0xB2B1B4`), cleanly slotted between `0xAB32F4` (`guild_raid_protection_persist`) and `0xAB3304` (`alex_heros_mark`). Note `0xAB3398` (`ret`) is dead code due to `0xAB3394` (`equipment_tier_upgrades`), so do not place new installers at `0xAB3398`.
- **Cave Budget**: `0xB2B1B4..0xB2B530` (`892 B`) inside `itanium_demangle::AbstractManglingParser::parseName` (`0xB2B098..0xB2B750`), plus a 48 B cooldown-helper trampoline cave at `0xB2B620..0xB2B650` in the same function's remaining free tail (`0xB2B530..0xB2B620` belongs to `trait_multi_unique`; `0xB2B650..0xB2B750` stays free; additional verified `demangler-only` candidates in [CODE_CAVES.md](CODE_CAVES.md)).
- **Shared Helpers inside Cave**:
  - `is_merlin_slot1_auto`: validates `skill._skillId == 1053188`, `_characterType == 0`, `_isAutoPlay != 0`, `_campType == 0`, and `_members[0] == caster`.
  - `slot_index_in_camp`: returns `0..Count-1` index in `Camp._members` — the original slot-order tie-break, kept in the cave but **no longer called** since `14.03` repointed both call sites to `awaken_power`.
- **Targeted Rules**:
  - `IsUseSupportSkillState` (`0x20EDBCC` / `0x20F1AF0`): accepts only living allies (`target != caster`, `_isDead == 0`) owning an Awakening skill (`(byte[sdata + 0x4d] | 1) == 5`) whose **true remaining cooldown == 1**. The check at `0xB2B3CC` tail-calls the client helper at `libil2cpp` RVA `0x1606428` (`IsAwakeningSkill ? Skill::GetCurrentCoolTime : -1`) through the `0xB2B620` trampoline cave, which preserves `x8`/`x9`/`x10`/`x30` around the call. Never test `[Skill + 0x30] == 1` directly: that field is a turns-elapsed counter (`Skill::ResetRemainCoolTime` `0x1B718E0` stores `0`), so any `_cooltime != 2` or Lord/stage/buff cooldown modifier desynchronizes it from the real remaining cooldown.
  - `CompareFindTargetStep + 0x178` (`0x20EEF2C` / `0x20F3338`): ranks reachable qualifying allies by `awaken_power` (see §4.2) instead of team slot order, falling back to the stock distance comparison when both candidates have the same rank (equal damage, or the same ally on different tiles). If no qualifying ally is reachable, `SupportFindTarget` returns `0` and Merlin attacks enemies normally.

### 4.1 `14.02` — Skill Priority over Bonus / Occupy / Item Cells (same option)

`14.01` decides *who* Merlin supports, but not *whether* she gets to cast at all:
`CharactersAI::InitActing` (`0x1A35F2C`) calls the virtual `MoveEnableToTile`
(`vtable[0x320]`) at `0x1A35F68` **before** any skill is evaluated, and that call
ends in `SetActionPhase(ai, 3)`. The following
`CharactersAI::NormalStateFindTargetWithPath` (`0x1A36494`) then reads
`[ai + 0x20]` at `0x1A364CC` and returns immediately, so the whole skill scan
(`NormalStateFindTakeSkillTarget` → `IsEnableUsingSkill` → `EnableUseSkillToTarget`)
never runs. Any reachable cell therefore outranks every skill.

Delivery: the 14.01 installer's tail `ret` (`0xB2B244`) becomes
`b 0xB30538`, a second cave in the dead
`itanium_demangle::AbstractManglingParser::parseEncoding` tail directly after
`dungeon_recom_info` (`0xB301F8..0xB30538`). It installs a fifth 4-word absolute
stub at the call site (`ldr x16, #8 ; br x16 ; <body>`), composed **at runtime**:
`movz`/`movk` write the two instruction words into a stack buffer and
`adr x9, installer_entry ; add x9, x9, #0xA8` supplies the body address. Never
store that address as a `.quad` in the cave: static literals are not relocated by
the dynamic linker, so the client would branch to the link-time VA and die with
`SIGSEGV` at `pc = 0xB305E0` (observed on-device, see `docs/HEROS_MARK_GUIDE.md`).

Body contract (`x19 = CharactersAI*`, `sp` = `InitActing`'s frame):

1. Guard: `owner = [ai+0x18]`, `[owner+0x18] == 0` (`_characterType`),
   `[owner+0x1c0] != 0` (`_isAutoPlay`), `[camp+0x18] == 0` (`_campType`),
   `Camp._members[0] == owner` (per the `BetterList` layout the 14.01 guard
   already uses), `[ai+0x90] == 0` (`appointedTile`), `[ai+0x98] == -1`
   (`appointedSkillIdx`).
2. Locate the support skill: scan `[ai+0x7c]` down to `[ai+0x80]` (descending
   start/stop — read the loop direction from the disassembly, the field names are
   the opposite of what they suggest), skipping `[ai+0x58]` (`preUsedSkillIndex`),
   comparing `[[[Skill+0x18]+0x10]]` against `1053188`.
3. Every index above it runs the **stock pair**
   (`CharactersAI::IsEnableUsingSkill` `0x1A36BA8` +
   `vtable[0x340]` = `EnableUseSkillToTarget` with `useportal = 1`, `x3 = [vtable+0x348]`);
   `true` → exit skipping the tile move. For Merlin this is slot 4
   (`1053189`, the Awakening attack), so a ready Awake is cast.
4. The support rung itself runs the stock **support branch only**:
   `AIStatePhaseFindSupport` `object_new` (`0xE4DD80`, typeinfo `[0x39D78A0]`) +
   ctor (`0x20ECE08`) + `AIStatePhaseController` `SetState` (`0x217E748`) /
   `Execute` (`0x217E83C`) / `IsExecuted` (`0x217E90C`). Do **not** call
   `EnableUseSkillToTarget` here: its fallback would build an
   `AIStatePhaseFindAttackPlayer` state instead of letting the cell move happen.
5. Exits: success → `0x1A35F7C` (unwind + `b NormalStateFindTargetWithPath`, which
   early-exits because the action is already committed); failure → replay the four
   displaced words and `0x1A35F78` (stock tile move).

Static client data (`0x3CD46E5` class-init guard, `0x39AD548` metadata-usage slot,
`0x39D78A0` typeinfo slot) must be read as `IL2CPP_BASE_CACHE + RVA` — a
PC-relative `adrp` in a server-lib cave resolves inside the wrong image.

Merlin data that makes `R4` cheap (all 7 creature rows identical,
`_combatType = 4`): `_skill0.._skill5` =
`[1053186, 1053187, 1053188, 1053185, 1053189, —]` — attacks at 0/1, *Magic
infusion* (ally, range 4) at 2, a **passive** at 3 (so it fails `IsActive` and
never reaches the vtable), and the Awakening attack (range 4, `_cooltime = 2`) at 4.
Only slot 4 can outrank *Magic infusion*; slots 0/1 keep losing to the cell.

### 4.2 `14.03` — Tie-break by Awakening-Skill Damage (same option)

Stock compares two `(moveTile, targetAlly)` candidates by walking distance, so
between two allies that are *both* already reachable the step count decided the
winner. `14.03` replaces that tie-break with the damage of each ally's
Awakening skill — distance stops mattering once the ally is in range.

- **Hook point**: nothing new is patched in the client. The two cross-ally calls
  in the `14.01` body (`0xB2B468` and `0xB2B474`, both `bl 0xB2B2F0`
  `slot_index_in_camp`) are repointed to `awaken_power` at `0xB3088C`
  (priority cave offset `0x354`, appended after the `14.02` body; cave 852 → 1112 B).
- **Rank convention**: `awaken_power` returns `0x7FFF - power`, so the untouched
  `cmp w0, w13` / `b.lt accept` pair keeps meaning "lower rank wins" and
  `0x7FFF` still marks "no value" — which now reads as *weakest*, so an ally
  without an Awakening skill can never displace one that has it.
- **Power source** (`SkillEffectTable`, resolved at runtime):

  | Step | Read | Meaning |
  |---|---|---|
  | 1 | `Character + 0x40` → `+0x18` → `+0x18` | skill container, array, count |
  | 2 | `array[+0x20 + 8*i]` → `+0x18` | `SkillData` of slot *i* |
  | 3 | `byte[SkillData + 0x4D]` `\| 1 == 5` | marks the Awakening skill |
  | 4 | `int[SkillData + 0x3C, +0x40, +0x44, +0x48]` | `_effect01..04` ids |
  | 5 | `SkillEffectTableManager::GetData(id)` (client `0x202730C`) | effect row |
  | 6 | `byte[row + 0x20] == 0` | `_skillEffectType` **damage** only |
  | 7 | `float[row + 0x38]` | `_effectValue` (`4.25` = 425%) |

  The multiplier is scaled by `100.0f`, truncated with `fcvtzs` and summed as an
  integer, so multi-effect Awakenings (e.g. `2.44` + `3.23`) total `567` instead
  of losing precision. Stun, heal and buff rows are skipped; a support Awakening
  therefore scores `0` and always loses to a damaging one.
- **Equal rank**: falls through to the stock distance comparison (same ally on
  several tiles, or two allies whose Awakenings deal the same damage).
- **Scope**: identical in PvE and PvP — the `14.01` guard already limits the
  path to the player's Slot-1 Merlin in Auto Mode; enemy teams and manual play
  never reach it. Reference values from `skilldata` + `skilleffecttable`:
  Merlin's Awakening `425%`, heavy hitters up to `730%`.

---

## 5. Workflow for Adding Future Auto Mode Hero Behaviors (Camilla, Serendi, etc.)

1. **Datatable Audit (`creaturedata*.unity3d`, `skilldata*.unity3d`, `skilleffecttable*.unity3d`)**:
   - Record all `_creatureId` variants (1★..5★ and Awakened; verify `_combatType` — remember Merlin is Balance `4`, not Support `5`!).
   - Inspect `_skill0`..`_skill4` (`_skillType`, `_skillTarget`, `_range`, `_skillEffectRange`, `_skillEffectRangeType`, `_cooltime`, `_useParameter`).
   - Check where the target skill sits relative to offensive skills in `_skill0`..`_skill4`:
     - If a buff/debuff sits at `_skill2` above attack skills `_skill0`/`_skill1` (like Merlin), `NormalStateFindTakeSkillTarget` (`4 -> 0`) already tests it before regular attacks.
     - If a desired support/utility skill sits at a **lower index** than an active offensive skill (e.g., `_skill1` vs `_skill2`), an additional hook in `PlayerAI::NormalStateFindTakeSkillTarget` (`0x18EA850`) is needed to test that support skill before lower-priority attack skills (while keeping `_skill4` Awake priority explicit).
     - If the skill has AoE geometry (`_skillEffectRangeType != 0`), also audit `SearchingManyTargetsCenterOfFindTarget` (`0x20ED47C`) to confirm whether AoE target-count maximization could shift away from a priority single target.
2. **Reuse / Extend the Shared AI Cave Router**:
   - Prefer consolidating multiple Auto Mode hero predicates under one shared AI module / cave table rather than burning scarce `0xAB3xxx` Covault sites per hero.
   - Preserve register contracts on every hook point (`IsUseSupportSkillState`, `CompareFindTargetStep`, and if added, `NormalStateFindTakeSkillTarget`) and verify both normal and `InPlace` paths.
   - **Calling client code from a server-lib cave**: when a rule needs a game
     value you cannot read off a struct field, call the game's own function
     instead of re-implementing its formula. Swap the minimum words in place
     (`bl` into a fresh trampoline cave + the comparison + the branch) and put
     the call sequence in a free tail slice: save every caller-saved register
     the surrounding loop still needs plus `x30` around the call, resolve
     `libil2cpp` from `IL2CPP_BASE_CACHE` (`0xBE3798`), build
     `base + client RVA` in `x16`, `blr`, restore, `ret`. Reference: the
     `0xB2B620..0xB2B650` trampoline of 14.01 (see the worked example below).
3. **Follow `fwt-add-patch` & Spec Kit (`specs/<NNN-short-name>/`)**:
   - Register all cave ranges in `validate_cave_layout()` (`core/core_patches.py`), wire independent verification in `core/patch_inspector.py`, assign a permanent Feature ID under Group `14` (`Auto-battle AI`) in `gui/feature_catalog.py` and [FEATURE_CATALOG.md](FEATURE_CATALOG.md), and prove every branch (positive, negative, self-exclusion, slot tie-break, fallthrough preservation, stack balance) with **ARM64 Unicorn emulation** tests before device verification.

---

## 6. Worked Example: The True-Cooldown Fix (`2.5.57`)

The 2.5.57 correction of `14.01` is the reference case for the full edit loop —
measure, root-cause on decrypted memory, design, trampoline, emulate, verify
payload. Reproduce this loop for every future Auto Mode behavior change.

1. **Symptom**: in-game test (Merlin Slot 1 + Neptunia Slot 2, Auto Mode) —
   Merlin kept attacking Minions instead of casting *Magic infusion* on the
   ally whose Awakening skill was 1 turn from ready.
2. **Live install check first** (never skip this): read decrypted memory at
   the hook sites — `base_il2cpp + 0x20EDBCC` held the trampoline and
   `base_server + 0xB2B1B4` matched `CAVE_BYTES`, so the hook *was* installed
   and the failure was logic, not delivery. Also compare the installed `.so`
   SHA-256 against the build's (`adb shell sha256sum`): a stale install
   invalidates the whole in-game test (the 2.5.57 investigation found the
   emulator running an older build).
3. **Root cause on decrypted memory, not on assumptions**:
   `Skill::ResetRemainCoolTime` (`0x1B718E0`) is `str wzr, [x0, #0x30]; ret`,
   so `[Skill + 0x30]` is a turns-**elapsed** counter the game zeroes and
   counts up — the old `== 1` test desynchronized from the real remaining
   cooldown for every `_cooltime != 2` and under Lord/stage/buff cooldown
   modifiers, in both directions (missed qualifying allies, accepted
   non-qualifying ones).
4. **Design rule**: never re-implement a game formula inside a cave — call
   the game's own function (`0x1606428`,
   `IsAwakeningSkill(skill) ? Skill::GetCurrentCoolTime(skill) : -1`). A
   re-implementation drifts the moment stock logic adds a modifier the cave
   author did not know about.
5. **Implementation shape**: a 3-word in-place swap at the check site
   (`0xB2B3CC`: `bl` trampoline, `cmp w0, #1`, `b.eq accept`) so no existing
   byte moves — the installer, both entry stubs, the tie-break hook and the
   literal pool stay untouched — plus a fresh 48 B trampoline cave in the free
   `parseName` tail (`0xB2B620..0xB2B650`, registered in
   `validate_cave_layout()`) that saves `x8`/`x9`/`x10`/`x30`, resolves
   `IL2CPP_BASE_CACHE`, and `blr`s `base + 0x1606428`.
6. **Proof, in two layers**: Unicorn emulation of both regression directions
   (`cd=3`/elapsed 2 accepted; `cd=3`/elapsed 1 rejected), every guard path
   unchanged, stack balance asserted; then extract the built APK's `.so` and
   byte-compare the swapped words and the tail cave — build-time
   "verification passed" proves packaging, not payload.
7. **Session hygiene**: long RE transcripts trip provider safety filters and
   kill coding sessions mid-investigation (see `AGENTS.md` RE Output
   Hygiene). Keep one investigation per session, disassembly in files under
   scratch/output, only short conclusions in chat, and hand off remaining
   work through a written file instead of retrying a blocked thread.
