# Hero Skill & Passive Rebalance Guide (Data-Only Benchmark)

This guide documents the end-to-end workflow for rebalancing existing heroes' active skills and passives by reusing or cloning native effects and range geometries from `fwt_0.682_offline_v1574.apk`, using **Alex** (`core/alex_rebalance.py` / Feature `12.02` `--alex-rebalance`, included in `--all`, and the thin CLI wrapper `tools/lab_alex_skill_rebalance.py`) as the reference benchmark.

Unlike adding a brand-new Awakening skill with custom runtime targeting (such as `Destiny Lance` in [PATCH_SPEC.md](PATCH_SPEC.md)), rebalancing skills already assigned to a hero using native `SkillEffectType`, `EffectConditionType`, and range geometries modifies **only client datatables** inside `assets/fwt_resources_v1.zip`—no `libil2cpp.so` code caves or `libfwt_local_server.so` changes are required.

---

## 1. Client vs. Server Boundary

| Component | Responsibility | Changes Needed for Existing Skill Rebalance? |
| --- | --- | --- |
| `lib/arm64-v8a/libfwt_local_server.so` | `kFwtCreatureSkillRows` (creature → `_skillId` list) and `kFwtSkillLevelCostRows` (gene upgrade costs). Does **not** store ranges, shapes, or combat effects. | **No**, as long as `_skillId` assignments and level costs stay unchanged. |
| `assets/fwt_resources_v1.zip` → `creaturedata*.unity3d` (8 locales) | Maps `_skill0`..`_skill4` and base creature stats. | **No**, unless swapping a hero's equipped skill IDs or base stats. |
| `assets/fwt_resources_v1.zip` → `skilldata*.unity3d` (8 locales) | `_range`, `_skillRangeType`, `_skillEffectRange`, `_skillEffectRangeType`, `_effect01`..`_effect04`, `_effectChance`, `_turnStart`/`_turnEnd`, `_cooltime`, `_useParameter`, and `_tooltip`. | **Yes** (all 8 localized bundles). |
| `assets/fwt_resources_v1.zip` → `skilleffecttable*.unity3d` (8 locales) | Effect definitions (`_skillEffectId`, `_skillEffectType`, `_precondition`, `_effectValue`, `_effectValueFactor`, icons, FX, etc.). | **No** if reusing an existing effect ID verbatim. **Yes** (all 8 bundles) when introducing tuned values under a new collision-free ID. |
| `assets/fwt_resources_v1.zip` → `skillfxdata.unity3d` | Animation prefabs, sounds, hit frames, and `_hit01`. | Usually **no**; verify visually in battle when changing geometry significantly. |

> **Isolation rule:** Never edit an existing `_skillEffectId` row in place if any other hero references it. Clone a verified donor row under a new collision-free ID audited across all 8 `skilleffecttable*.unity3d` bundles.

---

## 2. Hero Skill Slot Mapping (`creaturedata*.unity3d`)

Skill slots in `creaturedata*.unity3d` are zero-indexed:

| Field | In-Game UI Slot | Alex Reference (`0x130181`..`0x130186`) |
| --- | --- | --- |
| `_skill0` | **Skill 1** | `1048961` (*Piercing Lance*) |
| `_skill1` | **Skill 2** | `1048962` (*Valiant Charge*) |
| `_skill2` | **Skill 3** | `1048964` (*Giga-break*) |
| `_skill3` | **Passive** (`_skillType = 0`) | `1048963` (*Knighthood*) |
| `_skill4` | **Awake** (if present) | `-1` in stock (`0x100185` with `--alex-awakening`) |

Playable hero records use creature IDs with `(_creatureId >> 20) == 1` (boss/NPC variants share names under `0x33...` or other prefixes).

---

## 3. Core Engine Rules & Verified Contracts

### 3.1 Effect Slot Ordering (`_effect01`..`_effect04`)
Across all 4,000+ rows in `skilldataenglish.unity3d`, **zero** skills place primary Damage (`_skillEffectType = 0`) before a Final Power modifier (`_skillEffectType = 66`). When all 4 slots are used (e.g., Jin's *Cruelty* `1049428`), modifiers precede Damage, and Damage occupies the last active slot (`_effect04`).

### 3.2 Level Scaling Math & Float32 Quantization
- Standard hero skills have `_maxLevel = 10` in `skillleveltable.unity3d` (**9 upgrade steps** above Lv 1).
- Effective value at level $L \in [1, 10]$:
  $$V(L) = \text{\_effectValue} + (L - 1) \times \text{\_effectValueFactor}$$
- To hit target range $[V_1, V_{10}]$, set `_effectValue = V_1` and `_effectValueFactor = (V_{10} - V_1) / 9.0`.
- **UnityPy Float32 round-trip:** Unity serializes `MonoBehaviour` floats as IEEE-754 **float32**. Always quantize modified floats with `struct.unpack("<f", struct.pack("<f", x))[0]` before saving so round-trip equality checks (`decoded == expected`) pass deterministically.

### 3.3 Selected Native `SkillEffectType` & `EffectConditionType` IDs
Verified directly against `fwt_global_metadata_loopback.dat` and stock `skilleffecttableenglish.unity3d`:

| Category | ID | Native Enum / Meaning | Typical Usage |
| --- | --- | --- | --- |
| `SkillEffectType` | `0` | `Damage` | Primary active damage (`_effect03` or `_effect04`). |
| `SkillEffectType` | `18` | `APDownConst` | Flat Attack reduction (e.g., stock Alex Skill 2). |
| `SkillEffectType` | `59` | `APDownRate` | Variable `%` Attack reduction (`_effectValueType = 2`, negative values). |
| `SkillEffectType` | `66` | `FinalDamageUpByRate` | Utility Final Skill Power `%` modifier inside active skills (`_skillAffectedType = 5`). |
| `SkillEffectType` | `68` | `FinalDamageUpByRateBuff` | Buff Final Skill Power `%` modifier inside passives (`_skillType = 0`, `_effectTarget = 0`, `_skillAffectedType = 3`). |
| `SkillEffectType` | `97` | `CriticalHitDamageTakenDownRate` | Incoming critical damage `%` reduction. |
| `SkillEffectType` | `142` | `AllHitDamageTakenDownRate` | All incoming damage `%` reduction (`_effectValueType = 2`, negative values). |
| `EffectConditionType` | `255` | Unconditional | Always active. |
| `EffectConditionType` | `18` | `PerDoCoopPlay` | Cumulative trigger per cooperative attack. |
| `EffectConditionType` | `39` | `TargetDebuffCountIsGreaterThan` | Active when target has `>= _preconValue` debuffs. |
| `EffectConditionType` | `72` | `CasterAllyCountIsGreaterThan` | Active when `>= _preconValue` living allies are present. |
| `EffectConditionType` | `78` | `CasterCastingWithCoop` | Active during cooperative attack casting. |

> **Passive vs. Active placement:** Stock Alex put `23531569` (`type=66, precon=39`) inside Skills 1–3 rather than inside `1048963`, which left Skill 2 with no free slots once 4 effects were needed. Passives (`_skillType = 0`) support `type=68` (`FinalDamageUpByRateBuff`) with combat preconditions (`precon=39`, `precon=78`, etc.) directly inside `1048963` (matching Noel's `1050209`, Carrot's `1049441`, and *Blind Side* `2164259`).

### 3.4 Active Skill Range/Area Geometries (`skilldata*`)

| `(_range, _skillRangeType, _skillEffectRange, _skillEffectRangeType)` | Pattern / Reference Hero |
| --- | --- |
| `(1, 1, 0, 0)` | Melee adjacent single target (Kai, *Power Slash*) |
| `(2, 0, 1, 0)` | Range 2 single/cross-1 (Chenny, *Energy Ball*) |
| `(2, 0, 3, 8)` | **Lance Skill 2** (*Earthquake*, `1049219`) |
| `(4, 0, 0, 0)` | Range 4 single target (Ian, *Kitty Hunt!*) |
| `(2, 5, 2, 7)` | 2-tile piercing line (stock Alex Skill 1) |
| `(5, 5, 5, 7)` | 5-tile piercing line (stock Alex Skill 2) |
| `(3, 5, 3, 8)` | 3-tile line jump (stock Alex Skill 3) |
| `(3, 13, 3, 19)` | **Phantom Skill 1** (*Double Entendre*, `1050402`) |
| `(5, 13, 5, 19)` | **Sehee Skill 2** (*Blaze Rotary blade*, `1056851`) |
| `(2, 10, 2, 10)` | Radius-2 self-centered AoE (Muang, *Explosive Gas*) |

### 3.5 Localized `_tooltip` Placeholders (`@slot-format`)
- `@0-0`: `_effectChance` (%)
- `@0-1`: duration (`_turnEnd + 1`, so `_turnEnd = 0` prints `1` turn)
- `@N-3`: formatted percentage/value of `_effect0N` (`N` in `1..4`)
- `@N-2`: `_preconValue` of `_effect0N` (used in thresholds like *"While at least `{2}` allies are alive"*)
- Locale quirks in `0.682`:
  - `skilldatagerman.unity3d` and `skilldataspanish.unity3d` store `'-1'` for several skills—preserve `'-1'`.
  - Stock `skilldatajapanese.unity3d` for Alex Skills 1–3 had off-by-one damage tokens (`@2-3` / `@3-3`); normalize them when shifting slots.

### 3.6 Safe Packing & APK Build Pipeline
1. Decrypt each `.unity3d` bundle via `core.apk_tooling._decrypt_datatable`.
2. Update rows and serialize with `env.file.save(packer="original")` to preserve compression flags.
3. Re-encrypt via `_encrypt_datatable`, reload, and assert exact equality (`decoded == expected`) across all rows.
4. Build a dedicated DEV test APK (`--all --dev --dev-keep-version --dev-marker`) recomputing `ResourceContract.from_archive_path(...)` so `classes8.dex` matches the modified `fwt_resources_v1.zip`.
5. **Performance note:** Always run `fwt_patcher` / `zipalign` against local disk storage (e.g., a local SSD), not over SMB network shares, to avoid 600s `zipalign` timeouts.

---

## 4. Alex Benchmark Specification (`core/alex_rebalance.py` / `tools/lab_alex_skill_rebalance.py`)

### 4.1 New Collision-Free Effect Rows (`skilleffecttable*.unity3d`)
All 6 IDs were audited as unused across all 8 localized `skilleffecttable*.unity3d` files:

| New ID | Donor ID | `type` | `precon` / `pv` | Value (Lv 1 → Lv 10) | Purpose |
| --- | --- | --- | --- | --- | --- |
| `0x10018101` | `23072800` | `59` | `255` | `-10%` → `-30%` (`-0.20 / 9`) | Skill 2 variable `%` Attack reduction |
| `0x10018102` | `23531665` | `66` | `78` / `1.0` | `+10%` → `+25%` (`0.15 / 9`) | Skill 2 & 3 Co-op Final Power bonus |
| `0x10018103` | `23662625` | `68` | `78` / `1.0` | `+20%` flat | Passive Co-op Final Power bonus |
| `0x10018104` | `37818374` | `142` | `72` / `2.0` | `-5%` → `-25%` (`-0.20 / 9`) | Passive incoming damage reduction (`>= 2` living allies) |
| `0x10018105` | `23662625` | `68` | `39` / `1.0` | `+10%` flat | Passive bonus damage vs. debuffed enemies |
| `0x10018106` | `39915523` | `160` | `255` | `5.0` (`Thornbush`) | Awake `TileChange` (`MovingType.Thornbush`) |

### 4.2 Skill Updates (`skilldata*.unity3d`)

- **Skill 1 (`1048961` — *Piercing Lance*):**
  - Geometry from Phantom Skill 1 (`1050402`): `(3, 13, 3, 19)`.
  - Slots: `_effect01 = 24514561` (Move Atk%), `_effect02 = 23531665` (Ian Co-op `1%~10%`), `_effect03 = 16846913` (Damage), `_effect04 = -1`.
- **Skill 2 (`1048962` — *Valiant Charge*):**
  - Geometry from Sehee Skill 2 (`1056851`): `(5, 13, 5, 19)`.
  - Slots: `_effect01 = 0x10018101` (`-10%~-30%` Atk), `_effect02 = 17174567` (DoT), `_effect03 = 0x10018102` (Co-op `10%~25%`), `_effect04 = 16846914` (Damage).
- **Skill 3 (`1048964` — *Giga-break*):**
  - Cast range from Jakyak's *Do not Chase me* (`1056868`): `(3, 13)`. Alex's AoE remains `(3, 8)`.
  - Slots: `_effect01 = 17371140` (Stun), `_effect02 = 0x10018102` (Co-op `10%~25%`), `_effect03 = 16846915` (Damage), `_effect04 = -1`.
- **Passive (`1048963` — *Knighthood*):**
  - Replaces `26742786` (crit damage taken reduction) while keeping the debuff bonus (`+10%`) natively in `_effect01`.
  - Slots: `_effect01 = 0x10018105` (`+10%` vs. debuffed targets), `_effect02 = 0x10018103` (`+20%` in cooperative attacks), `_effect03 = 0x10018104` (`-5%~-25%` incoming damage while `>= 2` allies are alive), `_effect04 = -1`.
- **Terrain Advantage (`creaturedata*.unity3d`):**
  - Hero advantage tiles are stored as three byte fields (`_moveType0`, `_moveType1`, `_moveType2`) on each `CreatureData` row in `files/Resources/datatable/creaturedata*.unity3d` (8 localized bundles), using the `MovingType` enum:
    `Land = 0`, `Plain/Field = 1`, `Water = 2`, `Swamp = 3`, `Glacier = 4`, `Thornbush = 5`, `Lava = 6`, `Poison = 7`, `Sky = 8`, `SuddenDeath = 9`, `DeepWater = 10`, `None = 255`.
  - **Method used to add a second terrain advantage (`_moveType1`):**
    1. Identify every `_creatureId` belonging to the hero across all star grades and variants (for Alex: `1245569..1245574` for 1★–6★ plus `3342725`).
    2. Validate the baseline terrain slots (`_moveType0 == 1`, `_moveType1 == 255`) and assign `_moveType1 = 5` (`MovingType.Thornbush`), preserving `_moveType0` and all other fields.
    3. Read from `existing_replacements` before `archive.read(path)` in `prepare_alex_rebalance_assets()` so earlier `creaturedata*.unity3d` edits from `alex_awakening` (`_skill4 = 0x100185` on `1245574`) are preserved, save with `packer="original"`, re-encrypt with `_encrypt_datatable`, and verify round-trip equality across all 8 localized `creaturedata*.unity3d` bundles (`24` total tables alongside the `8` `skilldata*` and `8` `skilleffecttable*` bundles).
- **Awake (`0x100185` — *Destiny Lance*):**
  - Geometry: keeps global cast (`_range = 0, _skillRangeType = 2`) and single-target swap selection (`_skillEffectRange = 0, _skillEffectRangeType = 0`), with `_turnStart = 0, _turnEnd = 99` (100 turns, max standard byte duration in stock tables).
  - Slots: `_effect01 = 0x10018501` (unconditional 200% + 50%/lv Damage), `_effect02 = 21172225` (unconditional `PositionSwap`), `_effect03 = 0x10018106` (`TileChange` -> `MovingType.Thornbush = 5`), `_effect04 = -1`.
  - Swap & 1-cell Thornbush center: `Hook 5b` (`hook_take_skill_caster_tile` in `core/alex_awakening_client.py`) updates `castTargetTile` (`[x29 - 0x140]`) to the Boss's post-swap destination tile (`target._orgPositionTile`), temporarily sets `_skillEffectRange = 1, _skillEffectRangeType = 1` (`1 cell` Square), invokes `GameStage$$ChangeTileType`, and restores `_skillEffectRange = 0, _skillEffectRangeType = 0`.
  - Tooltip updated across all 8 `skilldata*.unity3d` bundles to document the permanent 1-cell Thornbush effect.

### 4.3 Commands & Verification Gates

```bash
# In-memory round-trip check across all 24 localized bundles
.venv/bin/python -m tools.lab_alex_skill_rebalance --verify-only

# Build dedicated DEV benchmark APK (run on a local SSD)
JAVA_HOME=/path/to/jdk21 .venv/bin/python -m tools.lab_alex_skill_rebalance

# Independent APK verification
.venv/bin/python -m tools.lab_alex_skill_rebalance --verify
```

### 4.4 Device / Emulator Benchmark Checklist
1. **Hero sheet (Lv 1 & Lv 10):** verify English tooltips, scaling (`10~30%` Atk down, `10~25%` co-op Final Power, `10%` vs debuffed, `20%` co-op, `2` living allies, `5~25%` incoming damage reduction), and both **Field** + **Thornbush** terrain advantage icons.
2. **Skill 1 (`1048961`):** verify Phantom `(3, 13, 3, 19)` targeting grid + Ian co-op bonus *(validated in Trial 1)*.
3. **Skill 2 (`1048962`):** verify Sehee `(5, 13, 5, 19)` grid, percentage Attack debuff (`D_SkillIcon_18`), and co-op damage increase.
4. **Skill 3 (`1048964`):** compare the cast grid with Jakyak's *Do not Chase me* and confirm Alex's existing AoE, Stun, and co-op damage increase.
5. **Passive (`1048963`):** verify `+10%` damage against debuffed enemies, `+20%` co-op bonus, and `-5%~-25%` damage reduction with `>= 2` living allies vs. `< 2` living allies.
6. **Awake (`0x100185` — *Destiny Lance*):** verify Alex lands on the Boss's original cell, 1-cell Thornbush terrain conversion centers on the Boss's destination cell (`boss_dest_tile`), persistence across turns (`_turnEnd = 99`), and adjacent minions are untouched.
7. **Non-regression:** confirm Ian, Sehee, Jakyak, and Phantom remain unmodified.
