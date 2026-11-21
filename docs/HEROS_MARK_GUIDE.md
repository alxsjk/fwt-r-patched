# Hero's Mark Creation and Reuse Guide

This guide documents the end-to-end process for adding a **Hero's Mark** (`partsType=3` Soul Gear) to a hero who never received one in the stock 0.682 client. The reference implementation is **The Unbroken Lance** for Alex (Feature `12.03`, `--alex-heros-mark`, [`core/alex_heros_mark.py`](../core/alex_heros_mark.py)).

Instead of authoring new textures or inventing untested passive mechanics, this approach reuses proven assets and patterns from existing marks—**Thanatos** for the mark icon and **Lily** for the two-effect passive structure—while introducing a **new client-side runtime hook** for the Level 10 Awakening skill cooldown reduction.

Detailed technical references: [patch specification](PATCH_SPEC.md), [code caves](CODE_CAVES.md), and [Hero Awakening guide](HERO_AWAKENING_GUIDE.md).

---

## 1. Design Summary (Reference: Alex's Hero's Mark)

| Component | Source / Pattern | Value / Behavior |
| --- | --- | --- |
| **Mark identity** | Cloned from Thanatos (`285749520`) | `_soulgearId=318865680` (`0x13018110`), `_creatureId=0x130181`, `_partsType=3`, `_choiceType=8` |
| **Artwork / Icon** | Reused from Thanatos | `_icon="UI_Icon_Markofhero_BlackDragon_01"`, `_iconFolder="Soulgear_Theme_100"` |
| **Base stats** | Mark stat block | `+380` Attack, `+2%` Crit Rate (`_cr=0.02`) |
| **Per-level skill boost** | `skilloverlaptable` (group `20490`, Lv `1..10`) | Destiny Lance (`0x100185`) gains `+25%` damage per level (`+250%` at Lv10) |
| **Set Effect 1** | Reused from Lily (`23667812`, `type 68`) | Team-wide `+20%` Final Skill Power (`_effectTarget=2`, `_precondition=255`) |
| **Set Effect 2** | Modified from Lily's second slot (`type 58`) | Team-wide `+10%` Attack while `>= 1` ally is alive (`_effectTarget=2`, `_precondition=72`) |
| **Lv10 Cooldown Reduction** | **New** `libil2cpp.so` runtime hook | Destiny Lance cooldown (`1 -> 0`) only when the mark is equipped and enchanted to Lv10 |

### Device Verification Results
- **Lv10 Cooldown Reduction**: Destiny Lance is castable on turn 1 when the Lv10 mark is equipped, while `skilldata` retains stock `_cooltime=1`.
- **Alex Awakening Damage**: `7,874,985` (without mark) → `11,364,813` (with mark), a `+44.3%` increase.
- **Ally Skill Damage on Boss**: `1,782,050` (without mark) → `2,126,342` (with mark), a `+19.3%` increase confirming both `+20%` Final Skill Power and `+10%` Attack propagate to allies.

---

## 2. What Must Be Changed

Adding a Hero's Mark to a hero without one requires synchronized changes across **40 UnityFS datatables** (5 tables × 8 locales) and **native binary patches** in `libfwt_local_server.so`:

### A. Client Datatables (8 Locales Each)

1. **`soulgeartable*.unity3d`**
   - Add the mark row (`_partsType=3`, `_number=10`, `_choiceType=8`) linked to the hero's `_creatureId`, a free `_skillGroupId`, and a free `_setgroupid`.
   - Clone an existing `partsType=3` donor (e.g., Thanatos `285749520`) to preserve the full schema, then overwrite the IDs, name, group IDs, and icon fields.
2. **`skilloverlaptable*.unity3d`**
   - Add 10 rows (`_equipLevel=1..10`) under the new `_groupId` targeting the Awakening `_skillId` (`0x100185`).
   - Set `_effect01ExtravalueType=1` and `_effect01Extravalue=_f32(0.25 * level)`.
   - Write literal `_desEquip` text per level; at Lv10, append `" Decreases Awakening Skill Cooldown by 1."` (standard equipment wording).
3. **`setitemtable*.unity3d`**
   - Add 1 row for the new `_setgroupid` (`_equipType=3`, `_setitemNum=1`, `_itemGrade=99`, `_setSkillid01=ALEX_SET_SKILL_ID`).
   - Build this row deterministically rather than blindly cloning a donor so foreign text/labels cannot leak through.
4. **`skilldata*.unity3d`**
   - Add the passive set skill (`_skillType=0`, `_skillTarget=2` for all allies) referencing `_effect01` and `_effect02`.
   - Keep the Awakening skill's own `_cooltime=1` untouched in `skilldata*`.
5. **`skilleffecttable*.unity3d`**
   - Add the two passive effect rows:
     - Effect 1 (`0x10018301`): `_skillEffectType=68`, `_effectTarget=2`, `_precondition=255`, `_preconValue=-1.0`, `_effectValue=0.20`, `_effectIcon="B_SkillIcon_68"`.
     - Effect 2 (`0x10018302`): `_skillEffectType=58`, `_effectTarget=2`, `_precondition=72`, `_preconValue=1.0`, `_effectValue=0.10`.

### B. Server Validation (`libfwt_local_server.so`)

- The embedded local server validates Soul Gear IDs against `fwt_valid_soulgear_idx::kIds` at **5 call sites** (`0x7EBDEC`, `0x7EC814`, `0x8B08A4`, `0x9A027C`, `0xA1B42C`).
- Without patching all 5 sites (via 28-byte stubs in the `0xB2AFDC..0xB2B068` cave), creating, granting, equipping, or inspecting parts for the new `_soulgearId` will fail server-side validation.

### C. Client Runtime Hook for Lv10 Cooldown Reduction (New Mechanism)

Because the stock game has no datatable field that reduces an Awakening skill's cooldown conditionally at Soul Gear level 10, this behavior is implemented as a runtime hook on `libil2cpp.so` installed from `libfwt_local_server.so`:

1. **Boot-time installer** at `0xAB3304` (post-Covault exit path) calls `PATCH_IL2CPP_HELPER` to patch the 4-word prologue of `Skill::GetCurrentCoolTime` (client RVA `0x16064B4`).
2. **Payload** in cave `0xB2FAA0..0xB2FBA0` (255/256 B):
   - Checks `Skill::SkillInfo.skillId == 0x100185` (Destiny Lance).
   - Reads the owner character's data container (`[x0, #0x10]` → `[x8, #0x20]`) and queries Soul Gear slot `partsType=3` via its vtable (`+0xa40` / `+0xa48`).
   - If the mark exists and its enchant level (`[x0, #0x30]`) is `>= 10`, returns `0`; otherwise replays the 4 displaced prologue instructions and branches to `0x16064C4`.

---

## 3. Precautions When Reusing Existing Effects, Icons & Tables

1. **Do not assume all 8 locales contain the same donor rows.**
   - Lily's effect row `23667812` exists in `default`, `chinese`, `english`, and `japanese`, but **does not exist** in `german`, `spanish`, `thai`, or `vietnamese` (which have 50 type-68 rows instead of 54).
   - Always fall back to any row with `_skillEffectType == 68` (or a full-schema dictionary built from scratch) and explicitly set `_effectIcon` and `_effectString`.

2. **Audit every ID across all 8 locales before choosing free IDs.**
   - Reusing `_setgroupid=30048` silently collided with the stock `"Vampire"` set, causing the client to display Vampire's name and effects instead of Alex's mark.
   - Verify `_soulgearId`, `_skillGroupId`, `_setgroupid`, `_skillId`, and `_skillEffectId` are unused in **every** locale bundle, and raise an error if a foreign `_setName` already occupies the target group.

3. **Stick to native Hero's Mark passive effect patterns.**
   - Equipment/rune target conditions such as `precondition=71` (`TargetMonsterTypeIsBoss`) are used on active attacks and debuffs in stock `skilleffecttable`, never on `type 68` passive buffs.
   - Device testing showed that using `precondition=71` on `ALEX_SET_EFFECT01_ID` (both with `_effectTarget=0` and `_effectTarget=2`) failed to apply the +20% boss damage bonus to allies (allies only received the `+2.4%` delta from `+10%` Attack).
   - Switching back to Lily's native pattern (`type 68`, `_effectTarget=2`, `_precondition=255`) immediately propagated the full bonus to allies (`1,782,050 → 2,126,342`, `+19.3%`).

4. **Respect ASLR in runtime trampolines.**
   - Never embed `.quad payload_entry` in a cave template copied into `PATCH_IL2CPP_HELPER`: static cave literals are not relocated by the dynamic linker.
   - Construct the trampoline on the stack at runtime using `adr x9, payload_entry` so the target address includes the live ASLR slide.

5. **Round float fields to IEEE-754 `float32`.**
   - DatatableMonoBehaviour fields serialize as 32-bit floats. Wrap float constants in `_f32()` so round-trip inspection (`_has_valid_mark_effects`) matches the exact values read back from UnityPy.

6. **Verify hook site and cave disjointness.**
   - Never reuse a branch site owned by another feature (e.g., `0xAB337C` belongs to `battle_arena_save_fix`, so `alex_heros_mark` uses `0xAB3304`).
   - Run `tests/test_suite_health.py`, `tests/test_gui_feature_parity.py`, and `core/patch_inspector.py` checks after every change.
