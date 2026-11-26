# FWT Re-Patched — Technical Specification of Patches & Tooling

> Living document. Last updated: 2026-11-19.
>
> Scope: Korean offline APK of Fantasy War Tactics **0.682 v1574**, embedded local
> server (`libfwt_local_server.so`), IL2CPP client (`libil2cpp.so`), and DEX
> (`classes8.dex`).

---

## 0. 2.5.35 Catalog Delta

The 2.5.35 release removed the demoted catalog rows and completed the
event/campaign shop fixes. Rows marked with a dash in Section 3 are historical
and are no longer selectable in the CLI or GUI.

- Removed: `select_all_4_5`, `equipment_option_factor`,
  `limit_break_cost_half`, `limit_break_gold_half`, `flask_3h`,
  `stamina_cashback`, and the recycling-ticket path.
- Added/changed: `gold_cylinder_x10`, `mana_cylinder_x10`; the client hooks for
  `single_gem_fang` (RVA `0x1DCACEC`) and the campaign/event shop client tables;
  `no_win_box` is now an unconditional bug fix.
- The release line is still `--all` plus the numeric factors; at `2.5.35`, `--all` covered 50 active features. As of `2.5.60`, `--all` enables **69** selectable features (plus default 16 KB alignment and the 4 always-on `no_win_box`, `hero_exp_cap`, `convert_hex_guard`, and `dungeon_recom_info` fixes; see [FEATURE_CATALOG.md](FEATURE_CATALOG.md)).

## Original hero modifications (12.01–12.03)

Feature `12.01` (`--alex-awakening`, `PatchOptions.alex_awakening`) adds Alex's
5★→6★ Awakening and Destiny Lance in 2.5.45. The implementation updates the
client evolution and 26 localized/shared skill tables, server evolution and
skill rules, and reference-specific client hooks. `--all` includes it; `--force`
is incompatible because the implementation requires the exact reference ELF.
Release builds suppress DEV skill telemetry. Native fingerprints and
the resource inspector must both pass before the feature is reported active.

Both the diagnostic prototype and the integrated release variant (without DEV
skill telemetry) were exercised on device in Guild Raid (Auto boss targeting,
manual boss-only selection, and boss position exchange), alongside Pit tests
covering target selection and no-boss availability. Its native code occupies
demangler routines: trap testing covered startup and battle on representative
paths, not every error or unwind path. See [HERO_AWAKENING_GUIDE.md](HERO_AWAKENING_GUIDE.md).

Feature `12.02` (`--alex-rebalance`, `PatchOptions.alex_rebalance`) rebalances Alex's
Skills 1–3 (`1048961`, `1048962`, `1048964`), Passive (*Knighthood*, `1048963`), and
— when `alex_awakening` (`12.01`) is also active — Awakening (*Destiny Lance*, `0x100185`)
via deterministic Unity asset-bundle patches in `core/alex_rebalance.py` across all 8
locales:
- Skill 1 uses Skill 2 (Valiant Charge) geometry `(5, 13, 5, 19)` and adds Ian Skill 1 co-op
  damage (`23531665`).
- Skill 2 keeps Sehee Skill 2 geometry `(5, 13, 5, 19)`, replaces flat Atk reduction with
  `-10%..-30%` percentage **Defense** reduction (`0x10018107`, DRDownRate type 132), and adds `+10%..+25%` co-op
  Final Skill Power (`0x10018102`).
- Skill 3 uses the cast range `(3, 13)` from Jakyak's *Do not Chase me*
  (`1056868`), retains Alex's AoE `(3, 8)`, and adds `+10%..+25%` co-op
  Final Skill Power (`0x10018102`).
- Passive keeps `+10%` damage vs. debuffed targets natively on `1048963` (`0x10018105`),
  replacing incoming crit damage reduction (`26742786`) with `+20%` co-op damage
  (`0x10018103`) and `-5%..-25%` incoming hit damage reduction while `>= 2` allies are
  alive (`0x10018104`).
- Terrain advantage: adds `MovingType.Thornbush = 5` as Alex's second advantage tile
  (`_moveType1 = 5`, alongside `_moveType0 = 1` Field) across all 7 Alex creature rows
  (`1245569..1245574`, `3342725`) in all 8 localized `creaturedata*.unity3d` bundles
  (while preserving `_skill4` when `alex_awakening` is also active).
- Awakening adds a permanent 1-cell Thornbush terrain conversion centered on the
  Boss's post-swap destination cell (`MovingType.Thornbush = 5`, `_turnStart = 0`,
  `_turnEnd = 99`), keeping single-target Boss selection/swap (`_skillEffectRange = 0`,
  `_skillEffectRangeType = 0`, `_effect01 = 0x10018501`, `_effect02 = 21172225`) while
  Hook 5b in `core/alex_awakening_client.py` invokes `GameStage$$ChangeTileType` at the
  Boss's destination tile (`target._orgPositionTile`) with a temporary 1-cell Square range.

See [SKILL_REBALANCE_GUIDE.md](SKILL_REBALANCE_GUIDE.md) for the verified client/server
architecture, float32 serialization rules, and future hero rebalancing workflow.

Feature `12.03` (`--alex-heros-mark`, `PatchOptions.alex_heros_mark`) gives Alex
the Hero's Mark *The Unbroken Lance* (`soulgearId 318865680`, `partsType 3`,
`number 10`, choiceType 8, skill group `20490`, set group `30051`) in all 8
locales, plus a set passives and a per-level Destiny Lance boost (`+25%` per
mark level, cumulative, `+250%` at Lv10 with cooltime `0`). It rewrites 36
resource tables and appends one archive member cloned from Thanatos's mark for
the icon. The per-level list text is written literally per row (like stock
group `4146`), and the Lv10 row adds the first-turn/cooldown line; the set
group id must stay clear of stock ids (`30048` is Camilla's "Vampire" set, which
the client showed as Alex's mark until the collision was fixed). Native side:
`fwt_valid_soulgear_idx::kIds` accepts the new id at all five inlined call
sites (`0x7EBDEC`, `0x7EC814`, `0x8B08A4`, `0x9A027C`, `0xA1B42C`) via 28-byte
stubs at `0xB2AFDC`, and the post-Covault installer at `0xAB3304` patches the
client `Skill::GetCurrentCoolTime` prologue (RVA `0x16064B4`, four words)
through `PATCH_IL2CPP_HELPER` into the cave payload at `0xB2FAA0`. The
installer resolves the payload address at runtime before building the
trampoline, preserving relocation under ASLR. A level-10 device test confirmed
first-turn availability and that battle starts without the previous crash;
the level-10 equipment description now uses the stock cooldown-reduction
wording. The set uses Lily's team-wide +20% Final Skill Power pattern
(type 68, `_effectTarget=2`, `_precondition=255`) alongside the +10% Attack
effect (`_effectTarget=2`, `_precondition=72`). The
installer deliberately does not use `0xAB337C`: that word belongs to
`battle_arena_save_fix` (25b) and a combined build must keep both. `0xAB3304`
is the `cbz w19` that splits the covault exit path, so every boot runs it; the
cave returns to `0xAB3308` when `w19 != 0` and branches to `0xAB335C` when
`w19 == 0`. Cave layout and site rationale: [CODE_CAVES.md](CODE_CAVES.md).

## 1. Target Architecture

| Component | File | Role | Notes |
|---|---|---|---|
| Local server | `lib/arm64-v8a/libfwt_local_server.so` | Embedded C++ (NDK) HTTP/JSON server listening on `127.0.0.1:8010` | ~13.38 MB, **unstripped**, ~701 `fwt::` symbols; per-PT_LOAD offsets (see Section 1.1) |
| IL2CPP client | `lib/arm64-v8a/libil2cpp.so` | C# game logic (Unity IL2CPP) | ~63.7 MB; protected by **AppSealing**: code pages are zeroed/encrypted at rest |
| IL2CPP metadata | `assets/bin/Data/Managed/Metadata/global-metadata.dat` | Types, methods, fields, strings, and RVAs | ~14.35 MB, metadata **v24**, statically readable |
| DEX | `classes8.dex` | Java/Unity bootstrap, localization and resource contract | apktool/smali rebuild + bytecode patches; SHA-1/Adler32 recalculated |
| Datatables | `assets/bin/Data/data.unity3d`, `datapack.unity3d` | Game tables (items, lab, stages, etc.) | Packed/encrypted; datatable/cache cipher keys configured in `.env` |
| Offline state | `fwt_server_state_v1.json` | Local server save/state | Stored under `files/fwt/` on the device; holds `LaboratoryCount`, `LaboratoryCooltime`, `stamina`, etc. |

### 1.1 Address Mapping

The values below describe the reference layout only. At runtime the patcher
and inspector parse the input ELF's file-backed `PT_LOAD` segments and map the
supported virtual ranges into a canonical buffer; writes are projected back to
the actual file offsets. Invalid, overlapping or unsupported mappings are
rejected. `seg_offset()` describes the canonical layout and must not be used
to modify an arbitrary raw ELF; use `read_load_segments()` and
`translate_vaddr()` for raw files.

- `libfwt_local_server.so`: `file_offset = vaddr - 0x4000` in the executable segment (`.text`).
- Relocatable read-only tables (`.data.rel.ro`): `file_offset = vaddr - 0x8000`.
- Pure `.rodata` tables: `file_offset = vaddr`.
- `libil2cpp.so`: metadata RVAs are virtual addresses; the binary at rest is
  AppSealing-protected, so static disassembly of method bodies generally fails.
- `classes8.dex`: raw file offsets within the DEX file.

---

## 2. Tooling & Roles

### 2.1 Runtime & Quality

| Tool | Pinned Version | Role | Status |
|---|---:|---|---|
| Python | >= 3.12 (venv 3.13/3.14) | Patcher and script runtime | Active |
| pytest | 9.2.0 | Unit and integration test suite | Active |
| ruff | 0.17.4 | Linting and import sorting | Active |
| mypy | 2.4.1 | Static type checking | Active |
| pytest-cov | 7.1.0 | Test coverage | Available |
| hypothesis | 6.170.15 | Property-based testing (idempotency, offsets) | Available |
| pre-commit | 4.7.0 | Pre-commit hooks | Available |
| pip-audit | 2.10.1 | Dependency vulnerability scanning | Active |
| python-dotenv | 1.2.4 | `.env` loading in CLI/GUI/tools | Active |

### 2.2 Binary / ELF / ARM64 Analysis

| Tool | Pinned Version | Role | Findings / Usage |
|---|---:|---|---|
| pyelftools | 0.33 | Inspect ELF sections, segments, symbols, and `PT_LOAD` | Mapped `vaddr → file_offset` and server symbols |
| capstone | 5.0.9 | ARM64 disassembly | Validated flask, stamina, coocoo, and potion instruction sites |
| keystone-engine | 0.9.2 | ARM64 assembly / trampoline encoding | Encoded `mov x21, #1000` and `add x0, x23, #1000` |
| unicorn | 2.1.4 | ARM64 emulation | Available; not required by current static patches |
| lief | 1.0.0 | ELF/APK inspection and manipulation | Available |
| Ghidra | 12.2 (JDK 25) | C++/ARM64 decompilation | Decompiled `refresh_laboratory_charge_state`, `laboratory_use_fields`, `use_potion`, `charge`, and `issue` |
| pwntools | 4.15.0 (isolated venv) | `ELF`, ROP, parsing, and REA integration | Optional isolated venv for ELF/ROP helpers |

> **pwntools + unicorn:** `pwntools 4.15.0` excludes `unicorn 2.1.3/2.1.4` in its
> package metadata. The isolated venv uses `unicorn 2.1.4` (prebuilt wheel) and
> `pwntools 4.15.0 --no-deps`; `from pwn import ELF` works normally. `pip check`
> only reports that metadata exclusion, which does not affect ELF parsing.

### 2.3 Client Runtime / IL2CPP

| Tool | Pinned Version | Role | Status |
|---|---:|---|---|
| frida-tools | 14.13.0 | Locate/validate RVAs, dump decrypted `libil2cpp.so`, test hooks | Available for runtime client inspection |
| REA | 6.8.0 (`npx rea-agents@latest`) | RE MCP/CLI: IL2CPP metadata, APK, ADB, ELF, pcap | Tested; decoded FWT metadata |
| Node.js | 24.22.1 (local) | REA runtime requirement | Installed on Windows workstation |

**REA findings on FWT:**

```bash
npx -y rea-agents@latest inspect-il2cpp-metadata \
  global-metadata.dat --binary libil2cpp.so --detail summary \
  --evidence_output evidence-il2cpp
```

- Metadata v24; 57 images; **14,614 types**, **111,579 methods**, **74,514 fields**,
  **19,800 string literals**.
- 105,483 method addresses linked to `libil2cpp.so`.
- RVA `0x1CE93F8` (Select All hook) → `EquipmentMenuGUI::BlockSelect`
  (`0x1CE9214`, offset `0x1E4`, size `0x5C4`).
- Limitations: `inspect-apk-signature` refuses APKs > 512 MB (ours is ~1 GB);
  `inspect-binary-layout` requires `pwntools` on Linux x64.

### 2.4 Data & Asset Exploration

| Tool | Pinned Version | Role |
|---|---:|---|
| polars | 2.1.0 (`rtcompat`) | Fast tabular analysis; compatible with CPUs lacking AVX2 |
| pandas | 3.1.1 | Tabular/CSV/JSON analysis |
| duckdb | 2.0.0 (1.5.6 on legacy CPUs) | SQL over JSON/CSV; 2.x requires AVX2/BMI2 |
| orjson | 3.13.0 | Fast JSON serialization |
| ijson | 3.6.0 | Streaming parser for large JSON files |
| jmespath | 1.1.0 | JSON querying |
| rich | 15.0.0 | Rich terminal formatting (optional) |
| typer/click | 0.28.0 / 8.5.1 | CLI helpers (optional) |
| pydantic-settings | 2.16.2 | Typed settings (optional) |
| adbutils | 2.12.0 | Python ADB library (optional; patcher uses `subprocess`) |
| UnityPy | 1.25.4 (via `uv --with`) | Read/repack `.unity3d` datatables (e.g., `laboratorycount`) |
| `tools/extract_env_keys.py` | UnityPy/cryptography | Extracts `.env` cipher credentials from the user's reference APK (prints key lengths only) |
| `tools/patch_labcount_datatable.py` | UnityPy/cryptography via `uv` | Patches `_cooltime=10800` in the external laboratory datatable |

### 2.5 Android / Linux Toolchain

| Tool | Version | Role |
|---|---:|---|
| JDK | Temurin 21.0.13 (Android) / 25.0.5 (Ghidra) | `apksigner`/`keytool`; Ghidra 12.2 requires JDK 25 |
| Android SDK build-tools | 35.0.0 | `zipalign`, `apksigner` |
| platform-tools | 37.0.1 | `adb` |
| apktool | 3.0.3 (auto-download, SHA-256 pinned) | Safe DEX/smali rebuild for bootstrap translation and resource contract |

---

## 3. Patch Catalog

For the current grouped GUI identifiers, CLI flags and selection defaults, use
the [Grouped Feature Catalog](FEATURE_CATALOG.md). The numbers in the table
and detailed headings below are historical technical references; they are not
the GUI's stable IDs. Entries marked removed are retained solely as history.

Status legend:

- **Active/validated**: byte sequences, counts, and inspector checks validated.
- **Runtime pending**: build and inspector pass; in-game visual behavior awaiting confirmation.
- **Blocked**: documented server/client limitation; see Section 5.

| # | Flag | Name | Target | Primary Addresses | Status |
|---:|---|---|---|---|---|
| 1 | `campaign_gold` | 10x Campaign Gold & Drops | SO | stage table `0x71D900`; hooks `0xA2C46C…` | Active/validated |
| 2 | `campaign_xp` | 10x Campaign XP | SO | stage table `0x71D900` | Active/validated |
| 3 | `gene_priority` | Hero Gene Drop Priority | SO | stage table `0x71D900` | Active/validated |
| 4 | `summon_rates` | Summon 70/20/10 | SO | pools `0xB95FD0`, `0xB96CF0` | Active/validated |
| 5 | `summon_rates_50_30_20` | Summon 50/30/20 | SO | pools `0xB95FD0`, `0xB96CF0` | Active/validated |
| 6 | `expedition_bonus` | 10x Expedition | SO | table `0xBBC2D0`; 5 call sites + cave `0xB333EC` | Active/validated |
| 7 | `english_localization` | English UI & Bootstrap | SO + DEX (smali) | gates `0xAA7CFC/0xAA7DB0`; Qty `0x4D5BA3`; 47 bootstrap strings + `saveCopy` | Active/validated (clean install, 2026-11-08) |
| 8 | `event_discount` | 90% Event Shop | SO | JSON `shop_content:2` | Active/validated |
| 9 | `event_gene_unlimited` | Unlimited Event Genes | SO + assets | JSON `item_category:18` (`limit_type: 255, limit_max: 9`); every localized `shopdata*.unity3d` gene row `_purchaselimittype=255`, `_purchasecountperlimit=255` | Active (server + client tables; 2.5.35) |
| 10 | — | ~~Mana Stone Compactor 3h~~ | — | Removed in 2.5.35 | — |
| 10b | `energy_flask_x10` | Energy Flask x10 Stamina | SO | `0xA65648` (`add x0, x19, #0x64` -> `#0x3e8`) | Active (1000 stamina, 2026-11-09) |
| 11 | `gold_cylinder_x10` | Gold Cylinder x10 | SO | hook `0xA65178` (`mov w8,#0x2710`) -> cave `0xB34CD8` (`level*100000+100000`) | Active (2.5.35; cave SHA pinned) |
| 11b | `mana_cylinder_x10` | Mana Stone Compactor x10 | SO | `0xA6585C` (`mov w9,#0x14`->`#0xc8`), `0xA65868` (`mov w11,#0x3c`->`#0x258`) | Active (2.5.35) |
| 12 | `event_coin_x10` | 10x Event Coin | SO | hook `0x8D05C0`, cave `0xB333CC` | Active/validated |
| 13 | `guild_raid_score_fix` | Guild Raid 64-bit | SO + client | `0x831CE4`, `0xAB00D8`, caves `0xB335C4/0xB33424` | Active/validated |
| 14 | `single_black_hammer` | 1 Black Hammer | SO | `0x8A7404` | Active/validated |
| 15 | `single_gem_fang` | 1 Dragon Fang Opens All 3 Slots | SO + client | server `0x7F5148` (`mov x24, #1`); server all-holes hook `0x8ADE80` -> cave `0xB2AD10` (`update_equipment_hole_json` for holes 1..3); late hook `0xAB3384` -> cave `0xB3367C` (RVA `0x1DCACEC` `b.le` -> `b`) | Active (2.5.47; 1 fang opens all 3 slots, client gate relaxed) |
| 16 | — | ~~Select All 4★/5★~~ | — | Removed in 2.5.35 (caused client freezes) | — |
| 17 | — | ~~Limit Break 50% (gold / gold+material)~~ | — | Removed in 2.5.35; only `limit_break_cost_tenth` remains | — |
| 18 | `coocoo_exp_x2` | Coocoo EXP x2 | SO | `0x7FCF30` | Active/validated |
| 19 | `stamina_cost_half` | 50% Dungeon Stamina (default in `--all`) | SO | `0x8D744C` | Active; used by `--all` (UI still displays/validates full cost) |
| 20 | `stamina_potion_1000` | Stamina Potion 1000 | SO | `0x8EC1E8` | Active; runtime validated (1000) |
| 21 | `lan_redirect` | LAN redirect | SO + DEX | shim `0xAB6858`; sites `0xAAD9F8…` | Active/validated |
| 22 | — | ~~Stamina Cashback 50%~~ | — | Removed in 2.5.35 (`tools/stamina_cashback.py` deleted) | — |
| 23 | `campaign_shop_discount` | 90% Campaign Shop Discount | SO + assets | JSON shop content 1, 3, 5, 6 + friend shop, `price_count`/`price_friendship_point`, nine category-6 `price_coin` rows and one assembled-price fragment; client `shopdata*.unity3d` `_friendPrice` and category-6 `_coinPrice`; `shopcontentsdata*.unity3d` `_purchaseNum` | Screenshot item prices verified in server response; debit pending |
| 24 | `mode_drops_x10` | 10x Mode Drops (6 Modes) | SO + assets | Unknown Paradise (`0x75EB90` 10x weekly, `0x8E69F4` 500+500 daily scales; event `10002` `0x75F6C0` preserved for Mobile Repair Shop), Honor grant `0x83FCF0` + rank points `0x95563C`, Dimension (`0x94B528`, genes `0x83C1E4`/`0x83C25C`), Nephthys item cave `0xB33734`, Library, Lost Island | Active (daily 500+500 scales, 10x weekly, Honor 60 coins / x2 points, Instant Repair preserved) |
| 25 | `battle_arena_fix` | Battle Arena Team Save Fix | SO | `0x95C698`, `0x95C750`, `0x95CAB0`, `0x8B5288`; PvP hooks `0x83A384`/`0x83A21C` -> caves `0xAC81B0`/`0xAC8200` | Active/validated |
| 25b | `battle_arena_save_fix` | Battle Arena Save (client hook) | SO installs client patch | late site `0xAB337C` (covault finalization epilogue) -> cave `0xB33634`; base from global `0xBE3798`; client RVA `0x1AA6FCC` `88029f9a` -> `e80314aa` (`mov x8, x20`) | Active/validated at runtime (client memory patched, no covault abort, 2026-11-10) |
| 26 | `guild_raid_mercenary` | Guild Raid Self-Mercenary | SO | hook `0x930100` -> cave `0xB34860`; reads the weekday hero and filters owned equipment, runes, costume and soulgears; when absent or invalid, resumes the selected stock hire | Active; no-costume and missing-weekday cases validated on emulator |
| 27 | `event_limits_daily` | Daily Event Shop Limits | SO + assets | JSON `limit_type=3` and `limit_type=4` -> `1`; client `shopdata*.unity3d` and `shopcontentsdata*.unity3d` type 3/4 -> 1 | Active (2.5.36; 1,423 server rows + event-shop counter hook + every localized client table) |
| 28 | `no_equip_drops` | Remove Equipment Drops | SO | stage table `0x71D900`, `equip_chance` at `+40` | Active/validated (431 stages, 2026-11-08) |
| 29 | `recycle_hammer_rewards` | Recycling Capsules Give Transcendence Tickets | SO | grade `0x89CCD0` -> `0xAC8240`; pick `0x9A3240` -> `0xAC8290`; completion `0x89D150` -> `0xB333A0`; selector `0x89CEF8` -> `0xB33820` | Removed in 2.5.35; historical only |
| 29b | `recycle_six_star` | Recycling Grants 6★ Equipment | SO + assets | `kFwtEquipRewardRows` `0x639760` rows in groups 102-111 -> 6★ set pieces with balanced set and piece weights; client `equipreward.unity3d`/`equiprewardjapan.unity3d` | Active (873 rows, `--all` default, 2026-11-09) |
| 30 | `upgrade_no_fail_above_20` | No Upgrade Failure Above +20 | SO | success table `0x6BAE64` | Active/validated (100% for +21..+26, 2026-11-08) |
| 31 | `limit_break_cost_half` | 50% Limit Break Cost (Gold + Fruit) | SO + assets (`limitbreakcost.unity3d`) | table `0x756CF0`, fields `+16` and `+20` | Removed in 2.5.35; historical only |
| 32 | `devil_boost_x10` | 10x Devil's Soul EXP Boost | SO | float `0x6C49D8` (2.0 -> 20.0) | Active/validated (31,900 EXP from one EXP Coocoo + Devil's Soul, 2026-11-08) |
| 33 | `sacred_lands_restore` | Restore Sacred Lands Set | assets (SetItemTable + EquipSelectList) | grade `4028` 1 -> 4 in all localized `setitemtable*.unity3d`; group `4028` added to ★4 lists `10001`/`10004`; critical hash `A6AE…` updated in DEX | Active/validated (device datatables: grade `[4, 4]`, ticket rows present, 2026-11-08) |
| 34 | `coocoo_level_x2` | Coocoo Level x2 | SO | Coocoo Garden / Pit of Nephthys stage table `0x735488`, 30 rows × 140 bytes, level fields `+68/+72`; 700xxx, 701xxx and 702xxx; final stage 220 -> 440 | Active/validated at runtime (Rock Garden 10 drops 4× level 440, 2026-11-08; 702 tier added for the post-reset bug) |
| 35 | `ship_parts_90_off` | 90% Off Battleship Parts | SO | `worldboss_ship_part_gold_cost` cost arrays `0x75F790` (30), `0x75F880` (10), `0x75F950` (4), 41 non-zero int64 values, `ceil(cost / 10)` | Active/validated at runtime (part 1→2 charged 500 instead of 5,000 gold; CLI/API alias `--ship-parts-half` / `apply_ship_parts_half`) |
| 36 | `crystal_skill_90_off` | 90% Off Core Crystal Upgrades | SO + assets | `WORLDBOSS_SHIP_SKILL_LEVELUP` immediate `0x84A2C0` (50 -> 5 Kraken Scales); 29 `crystalskillcost.unity3d` rows (50 -> 5) | Active/validated at runtime (skill 1→2 charged 5 scales, 590 → 585, 2026-11-08) |
| 37 | `gem_mining_x10` | Gems x10 (Mining) | SO | `GemMiningStateAccess::mine` count site `0x8AB110`; cave `0xB33830` | Active (10 gems per roll, including the 20-crystal paid roll) |
| 38 | `gem_mining_types` | Gem Type Restriction | SO | `GemMiningStateAccess::mine` index site `0x8AB08C`; cave `0xAC8260` | Active (MP/Counter/Dodge/Hit only) |
| 39 | `gem_upgrade_gold_half` | 50% Off Gem Upgrade Gold | SO | `GemStateAccess::graft` fee site `0x8ACA6C`; `sub x0, x22, x26` -> `sub x0, x22, x26, lsr #1` | Active (actual gold debit halved) |
| 39b | `gem_level6` | Gems Level 6 | SO | 9 gem-code strings at `0x21BD6F`, `0x4D4F78`, `0x499897`, `0x5FE5E8`, `0x3B2D83`, `0x2A3B7E`, `0x41516C`, `0x546E6C`, `0x505EC3`; last digit `1` -> `6` | Active/validated at runtime (lobby gem screen gives level-6 gems, 2026-11-09) |
| 40 | `guild_raid_reward_x10` | Guild Raid Rank Rewards x10 | SO | tables `0x758260` / `0x7583A0`; 32 amounts x10 | Active (daily + weekly mails, 2026-11-09) |
| 40b | `option_max_attributes` | Max Quality on Every Option Roll | SO | Transfer each attribute and equipment-grade pool's roll weight to its highest-quality rows, using the quality table at `0x634060` | Active (enabled by default in the GUI and `--all`; compatible with percentage-only rolls) |
| 42b | `equipment_single_mod_stone` | One Modification Stone | SO + client | server `equipment_option_change_material_count_json` `0x8A4DC8`, site `0x8A4F3C` (`csinc` -> `mov x0, #1`); client hook `0xAB3388` -> cave `0xB337B4` patches `0x1CF069C` (`mov w1, w23` -> `mov w1, wzr`) | Active/validated at runtime (cost label and confirmation show 1 stone; server charged exactly one with two locked lines) |
| 42c | `equipment_percent_options` | Percent-only Equipment Options | SO + assets (`randoptiontable.unity3d`) | server table `0x621E60`, 1856 rows × 40 B, direct and scaled flat groups -> six grade weights zeroed plus the zero-weight picker fallback at `0x9A2AAC`; client value types 1 and 4 -> all six `_weightN` zeroed | Active (weights + fallback) |
| 42d | `equipment_upgrade_10_guarantee` | +10 Upgrade Always Succeeds | SO + assets (`equipsuccessprobability.unity3d`) | fail-probability table `0x6BC118` index 9 (`0x6BC160`, 8 B) `595082` -> `0`; client `equipsuccessprobability` row 9 also `_successProb1..6=100000` | Active/validated at runtime (10/10 direct server requests went +9 -> +10; +10 -> +11 still fails) |
| 42 | `equipment_lock_fix` | Locked Options Survive the First Roll | SO | NOP at `0xA18354` (`EquipmentStateAccess::change_option` `0xA1832C` calling `refresh_equipment_options_for_code_json` `0xA16FB8`) | Active/validated at runtime (0 lock violations after the fix; before it 10 violations in 17 transitions) |
| 43 | `rune_quality_factor` | Rune Attribute Quality x10 + Percent Only | SO + assets (`runeoption.unity3d`) | `rolled_rune_options_json` `0xA2E65C`: bonus load at `0xA2EB90` -> `movz x9, #min(10000, 450 * factor)`; 420 flat weights zeroed in the verified rune option table at `0x6ED510` and in the client `runeoption.unity3d` rows (`_valueType=1` -> `_weight=0`) | Active (server + client tables); device validation pending |
| 43b | `rune_option_quality` | Rune Options Max Mastery Row | SO | `rolled_rune_options_json` `0xA2E700` (`bl mastery_level_in_state` -> `mov x0, #0xf`) plus the `kFwtRuneOptionRows` weight rewrite | Active (always indexes the mastery level 15 weight row at `0x719F10`; only each pool's top-quality rows keep weight) |
| 44c | `rune_upgrade_discount` | +12..+15 Rune Upgrades Guaranteed + 90% Off | SO + client code | `kFwtRuneEnchantRows` `0x75797C` rows 12–14, `rune_decided_enchant_cost_json` `0x914F2C`, client cave `0xB2A360` (hook `0xAB338C`) rewriting `0x1C5B484` | Active (no failure weights, gold ÷ 10, Awake shows 95,060) |
| 44 | `rune_box_random_roll` | 4★ Rune Box Rolls Slot and Type | SO | `pick_battle_rune_code` `0x982C1C`: `0x982F04` (`-slot`) and `0x983178` (type loop seed) -> cave at `0xB3981C` (68 B, xorshift32); `0x982D2C` (`-grade`) and `0x983024` (`-quality`) stay deterministic | Active/validated at runtime (2026-11-12) |
| 44b | `rune_box_random_type` | 4★ Rune Box Type Table | SO | `kFwtRuneRewardTypeRows` `0x61E134`, rows 11..13 -> group 9, weight 1000, types 0/1/2 | Active (covers reward-mail table path; shop box path also uses `44`) |
| 45 | `limit_break_cost_tenth` | 90% Hero Limit Break Cost | SO + assets (`limitbreakcost.unity3d`) | `kFwtCreatureLimitBreakCosts` `0x756CF0`, 45 rows x 24 B, quantity `+16` and gold `+20` divided by 10 | Active; mutually exclusive with `limit_break_cost_fixed` |
| 45b | `limit_break_cost_fixed` | Flat Hero Limit Break Cost (1M gold + 100 Balance Jade) | SO + assets (`limitbreakcost.unity3d`) | `kFwtCreatureLimitBreakCosts` `0x756CF0`, all 45 rows: quantity `+16` = 100, gold `+20` = 1,000,000; client rows `_rewardValue02`/`_cost` set to the same pair | Active; shipped by `--all`; mutually exclusive with the 90% profile |
| 46 | `soulgear_enchant_always` | Soulgear Enchant Always Succeeds | SO | `SoulgearGrowthStateAccess::apply`: verdict `cset w8, lo` at `0x8B3B4C` -> `mov w8, #1` | Active; gold-paid enchant always succeeds (soulgear upgrade has no roll) |
| 47 | `no_win_box` | Hide Phantom Coocoo Boxes | SO | Battle advertisement off at `0x8DA77C`; Subjugation box gate at `0x8CFC7C` skips bonus boxes for mapped hero-gene stages | Always active |
| 48 | `guild_raid_fire_support` | Guild Raid Fire Support (100% HP + Minion Auto-Cast) | SO + client + assets (`guildskilldata.unity3d`) | `guildskilldata` effect `1048578` -> `_value01=1.0, _value01Factor=0, _value02=0, _value02Factor=0`; runtime hook `0xAB335C` -> `0xB2ABC0` gates `0x018E7060` (`Player$$ExecuteReservedLordSkill`) on `GetEnemyWithoutBossMultiTargets().Count > 0` for `0x20000002` | Active (100% maxHp on minions; reserved auto-cast holds until minions spawn on map; other skills unchanged) |
| 49 | `guild_raid_skills_max` | Guild Raid Skills Maxed (1M / 100%) | assets (`guildskilldata.unity3d`, `guildskillinfo*.unity3d`) | Effects `1048577` (1M flat boss dmg), `1048579` (100% 1-hit DR), `1048580` (100% HP), `1048581` (100% MP), `1048582` (20 debuffs dispelled), all factors `0.0`; Absolute Protection (`536870915`) also links `effect03=1048581` (`target=1`) across all 8 `guildskillinfo*` bundles | Active (composes orthogonally with `guild_raid_fire_support`) |
| 50 | `guild_raid_boss_no_counter` | Guild Raid Boss 0% Counter Rate | assets (`monsterdata.unity3d`) | All 70 Guild Raid boss rows (`400-01`..`400-07` host + spawn levels 1..9, `_boss == 100`): `_car = -1.0` -> `0.0` (overrides `CreatureData._baseCar = 0.03`) | Active (all Guild Raid bosses at 0% counter rate) |
| 52 | `guild_raid_protection_persist` | Absolute Protection Persists for All Hits | SO (runtime client patch) | mid-function hook `0xAB32F4` -> cave `0xB2AE18..0xB2AFC0` (424 B) patching client RVAs `0x1877C60` (`bl RemoveMultiTarget` -> `bl GetMultiTarget`), `0x1BAA2FC` (`b.lo -> nop`), and `0x1BAA318` (`b.ne -> nop`) via `PATCH_IL2CPP_HELPER` + `mprotect` fallback | Active (07.09; shipped in `--all`, protects all hits for full 1-turn duration) |
| 51 | `hero_exp_cap` | Hero EXP Cap & Limit Break Floor | SO | `creature_level_max_value_json` floor `0x902008` -> `mov w20, #0x46 ; b 0x9020b8`; battle/expedition EXP hooks `0x80963C`, `0x81831C`, `0x945E30` -> cave `0xB2AD70` (`creature_max_total_exp_for_level_json`) | Always-on bug fix; prevents Lv71 EXP overflow and unlocks Limit Break for existing Lv71 un-transcended heroes |
| 53 | `convert_hex_guard` | Non-Hex Inventory Sync Guard (KB-001) | SO (runtime client patch) | post-Covault installer `0xAB3370` -> cave `0xB2B098` patching `UtilFunc$$ConvertHexU32+0x94` (`0x0181178C`) to return `-1` on non-hex/`>8`-char `item_code` strings instead of throwing `FormatException` | Always-on bug fix (`08.07`); prevents `OnGetMyItemInfo` from aborting on corrupted template rows (`13000K`, `13000Y`) so later items (`2040031` Mythical Stones, `200002` Green Gems) load on restart |
| 54 | `trait_max_quality` | Traits: Max Quality Rolls (Grade 5 / Pink) | SO | `kFwtPotentialDataRows` (`0x6CBBC8`, 393 rows × 68 B) + `kFwtPotentialGradeRows` (`0x6D242C`); 58 weighted `(potential_type, slot_phase)` pools concentrate 100% weight on grade-5 rows (`130` lower/top rows updated) | Active (13.01; keeps exact per-attribute odds while guaranteeing grade 5 on every Trait roll) |
| 55 | `trait_allow_duplicates` | Allow Duplicate Hero Traits Across Slots | SO | `choose_potential_code_json` (`0x8BFDF0`), site `0x8BFF74` (`b.eq 0x8C00F0` -> `b 0x8C00F0`) | Active (13.02; bypasses cross-slot `potentialType` `std::set` exclusion while keeping `w4 = 1` current-slot `pt_code` exclusion) |
| 56 | `limit_break_step_10` | Limit Break +10 Levels (to Lv 120) | SO + assets (`limitbreakcost.unity3d`) | `kFwtCreatureLimitBreakCosts` `0x756CF0`, 45 rows x 24 B, `level_after` (+4) / client `_levelAfter` set to `min(120, ((level_before // 10) + 1) * 10)` | Active (13.03; shipped by `--all`, orthogonal to cost profiles) |
| 57 | `merlin_auto_support` | Merlin Slot-1 Auto Support (Magic infusion on Awake CD==1) | SO (runtime client patch) | post-Covault installer `0xAB3300` -> caves `0xB2B1B4..0xB2B530` (892 B) + `0xB2B620..0xB2B650` (48 B awake-CD trampoline calling client `0x1606428`) patching `AIStatePhaseFindSupport`/`InPlace` `IsUseSupportSkillState` (`0x20EDBCC`, `0x20F1AF0`) & `CompareFindTargetStep+0x178` (`0x20EEF2C`, `0x20F3338`) via `PATCH_IL2CPP_HELPER` | Active (14.01 + 14.02 + 14.03; Slot 1 + Auto Mode only, true remaining Awakening cooldown via `GetCurrentCoolTime`, skills before bonus/item cells, tie-break by strongest Awakening-skill damage instead of slot order, keeps healing rules & enemy fallback untouched) |
| 58 | `trait_multi_unique` | Traits: Unique Attributes per Multi-Roll Batch | SO | `REQ_CHANGE_CREATURE_POTENTIAL` (`0x7FF69C`, `0x7FF7F4`) + `choose_potential_code_json` (`0x8BFE30`, `0x8C01E8`, `0x8C0524`, `0x8C07C8`) -> cave `0xB2B530..0xB2B620` (240 B) tracking a 63-bit batch `potentialType` bitmask in callee-saved `x27` | Active (13.04; shipped by `--all`, composes with `trait_allow_duplicates` `13.02`, falls back gracefully if candidates exhaust) |
| 59 | `trait_immunity_weight_x2` | Traits: Double Immunity Weights (Slots 3-5) | SO | `kFwtPotentialDataRows` (`0x6CBBC8`) rows `300` (`id=35001, col=6`), `301` (`id=36001, col=12`), `302` (`id=37001, col=9`): stock weight `335` -> `20000` (2x normal `10000` stats) | Active (13.05; shipped by `--all`, orthogonal to `trait_max_quality` `13.01`) |
| 60 | `dungeon_recom_info` | Mercenary Auto-Select Recommendations (`DUNGEON_RECOM_INFO`) | SO | `fwt::EmbeddedStub::handle_json_request` dispatch call `0x7DAED0` (`bl 0x7E4030`) -> cave `0xB301F8` (832 B, parseEncoding family): byte-scans the request for `"DUNGEON_RECOM_INFO"`, forwards other CMDs untouched, answers `recom_list` via `load_state_snapshot` (`0x7DDECC`) + `friend_list_json` (`0x8D5674`) + `int_field` packet_no echo (`0x7E08B8`), plain-ack fallback when the state cannot load | Always-on bug fix (08.08); the pre-battle "auto select" finally receives candidate mercenaries |

| 61 | `guild_raid_skill_turn_gate` | Guild Raid Lord Skills Auto-Cast Once per Turn | SO + client (runtime) | boot word `0xAB3374` (`mov w4, w19` -> `bl` cave `0xB30990`, 388 B) installs the 4-word absolute stub over `Player$$ExecuteReservedLordSkill` RVA `0x018E6FF0` (expected `0x2A1403E0, 0xAA1F03E1, 0x97FC1B68, 0x370019C0`) via `PATCH_IL2CPP_HELPER`; the body replays the block and gates `0x20000001/0x20000003/0x20000004` on `{instance, turn, mask}` at `0xBE62C8` -> hold `0x018E7334` / mark + resume `0x018E7000` | Active (07.10; shipped in `--all`; Fire Support `0x20000002` untouched) |
Build & infrastructure fields on `PatchOptions` (not gameplay patches): `server_ip` / `server_port` (target endpoint when `lan_redirect` is enabled, defaults `127.0.0.1:8010`), `align_16k` (Android 16 KB page alignment, default `True`, disabled with `--no-16k`), `allow_unknown` (bypass reference-APK guard via `--force`), and `dev` (`DevOptions`, documented in [`docs/DEV_BUILD.md`](DEV_BUILD.md)).

### 3.1 Per-Patch Details

#### 1. `campaign_gold` — 10x Campaign Gold & Drops

- **Stage table**: `STAGE_TABLE_OFFSET = 0x71D900`, 942 rows × 140 bytes.
- For stages with hex prefix `10`, `11`, `12`:
  - gold at `+8` → `gold * 10`;
  - stamina at `+128` → `stamina * 10`.
- **Trampolines** at `0xB33314` (non-overlapping code cave inside unreferenced demangler function):
  - gold `0xA2C46C`/`0xA2C9A0`;
  - gene `0xA2CC44`;
  - mana `0xA2C644`/`0xA2CAD0`;
  - items `0xA2D0D4`/`0xA2D6C4` -> cave `0xB33734` (extended for Nephthys and
    Lost Island prefixes; stores the 0/1/2 flag at `[sp]`).
- Reference count: **381** rows.

#### 2. `campaign_xp` — 10x Campaign XP

- Same stage table; hero XP at `+4` and Lord XP at `+12` multiplied by 10x.
- Reference count: **381** rows.

#### 3. `gene_priority` — Hero Gene Priority

- Same stage table; `gene_weight` at `+22*4` and `gene_id` at `+23*4`.
- Stages `10/11/12/80/81` with gene > 0: `weight = max(gene_weight, highest_other_weight + 1)`.
- Reference count: **141** rows.

#### 4/5. `summon_rates` / `summon_rates_50_30_20`

- Pools:
  - `bonus`: `0xB9DFD0 - 0x8000 = 0xB95FD0`, 84 rows of 40 bytes;
  - `normal`: `0xB9ECF0 - 0x8000 = 0xB96CF0`, 144 rows.
- Row layout: `<iii>` weight, category, rotation; byte `+12` = special flag.
- Categories: 3 = 4★, 4 = 5★, 5 = 6★.
- Profiles:
  - 70/20/10: `{3:700000, 4:200000, 5:100000}`;
  - 50/30/20: `{3:500000, 4:300000, 5:200000}`.
- Largest-remainder apportionment preserves relative weights within each rarity tier.
- Reference count: **228** rows (84 + 144).

#### 6. `expedition_bonus` — 10x Expedition

- Table `0xBC42D0 - 0x8000 = 0xBBC2D0`, 19 regions × 120 bytes; hero XP at `+16` multiplied by 10x (`13200` on row 1).
- Trampoline hook at `0xA75904` branches to code cave at `0xB333EC`, multiplying rolled reward quantities by 10x (`mul x19, x19, x8` where x8=10).
- Reference count: **24**.

#### 7. `english_localization` — English UI & Bootstrap

- SO gates:
  - `0xAA7CFC` → `0xAA7D40` (string table);
  - `0xAA7DB0` → `0xAA7E24` (message box).
  - Quantity text at `.rodata 0x4D5BA3`: Korean `'수량\x00'` → ASCII `'Qty\x00\x00\x00\x00'`.
- DEX `classes8.dex` (smali rebuild through apktool 3.0.3):
  - Translates all **47 unique hard-coded Korean bootstrap strings** (51
    `const-string` occurrences) across `FwtResourceBootstrapActivity*`:
    title, status, progress format, save-data prompts, failure details and the
    **Retry** button.
  - Replaces `FwtResourceBootstrapActivity.saveCopy()` with
    `return-object p1`, so every bilingual bootstrap prompt uses the official
    English copy.
  - apktool/smali reassembles the DEX, so the string table is re-sorted and
    ART's lexical verification passes. The old in-place rewrite changed the
    values without re-sorting and caused an instant ART abort.
  - `core.dex_smali.verify_dex_string_order()` checks the final table before
    packaging; SHA-1 and Adler32 are recalculated by the assembler.
- Reference count: **55** modifications (2 SO gates + 1 Qty label + 51
  translated literals + 1 `saveCopy` branch).

#### 7.1 Bundled resource archive contract

`assets/fwt_resources_v1.zip` contains `laboratorytimezone.unity3d` and
`honorreward.unity3d`. Patching either file changes the archive bytes, so the
bootstrap's integrity contract must be updated in the same build:

- Original 0.682 v1574 contract: SHA-256
  `A687D7C576D98EFED71AA3748B8FDB96F28AF70B4E6777719E1474FA0B3C7BBD`,
  `files=8697`, `bytes=870464600`.
- The build computes `ResourceContract.from_archive()` from the final patched
  archive and rewrites, through the same smali pass:
  - `ARCHIVE_SHA256`, `MARKER_NAME`, `MARKER_CONTENT` and every marker literal;
  - `EXPECTED_FILE_COUNT` and `EXPECTED_UNCOMPRESSED_BYTES`;
  - the `isInstalled`, `writeMarker` and `cleanupObsoleteMarkers` copies.
- Current 2.0.1 contract: SHA-256
  `54AA3B7581DFC4134CA77BBA55086E04C2788619FA1B6EA36B1E1BD14FB42A93`,
  `files=8697`, `bytes=870472376`.
- The rewrite preserves every untouched ZIP local record and replaces only the
  two datatables (stored uncompressed), so the archive SHA is identical on
  Windows and Linux.
- Without this update a fresh install fails with
  `내장 리소스 크기가 계약을 초과했습니다.` / *Resource size exceeds the
  expected limit*. Existing installs appear to work only because the marker and
  extracted resources are already present.

#### 8. `event_discount` — 90% Event Shop

- Regex match on JSON rows with `"shop_content":2`.
- `price_count` charged at 10% of the original value (`ceil(price / 10)`),
  padded with leading spaces to preserve exact byte length.
- The regex is scoped to a single JSON object (lookaheads inside `[^{}]*`), so
  it cannot match a `price_count` from a neighboring campaign row. The two
  cross-object matches that inflated the old 124 count are gone.
- Reference count: **122** rows.

#### `mythical_stone_shop` — Mythical Stone in Event Shop (02.07)

- Replaces event 278 offer `2330278` with item `2040031` (one Mythical Stone), price 50 event coins, daily limit 100. Offer `2331278` remains Balance Jade (20 units) with a daily limit of 20 purchases.
- Updates both copies in the embedded server catalog in place after price and limit patches. Native period maintenance and purchase-count checks remain in place. On the disposable emulator, the UI displayed 50 coins and 0/100, one purchase added item 2040031 and charged 50 coins, the 100th Stone and 20th Jade purchases succeeded, and both offers were blocked afterward. Moving the test save to the next daily period reset both counters to zero.
- Names are shortened in some language slots to fit the fixed-size native records; one Balance Jade label loses an internal space.
- **Known limitation ([KB-001](KNOWN_BUGS.md))**: purchases are charged, delivered, persisted, and usable in the same session, but the client inventory and costume enchant display reset to zero after a game restart. Server-side state is preserved; spend the stones in the session in which they are bought.

#### `hero_shop_offers` — Evan and Alex Shop Offers (02.09)

- Replaces event 278 costume offer `2250278` with one Evan gene (`120741`) for 5 event coins and Honor Shop Diamond offer `1103` with one Alex gene (`130181`) for 1 medal. Both use the native unlimited sentinel `255/255`.
- Changes Honor offer `1104` from 60 to 100 Diamonds while retaining its price and limit. Native catalog copies are verified and rewritten without resizing, including its NUL-terminated fragment. One localized Diamond label becomes `Diamond` to fit the new count.
- The fixed hero prices apply after the existing shop discount and limit patches. Static and integration checks do not establish runtime delivery or UI behavior; device validation remains pending.

#### `surprise_transcendence_package` — Surprise Transcendence Package 2 (02.10)

- Surprise Sale offer `75103` uses isolated package `103899` for 500 diamonds.
- The package delivers ten Ultimate Equipment Transcendence Tickets (`130006`) and ten Universal Transcendence Tickets (`130000`) through the normal package delivery flow.
- Six checked native catalog records preserve JSON slot lengths and other offers' original package `103114`. The target listing comes from the server catalog.

#### 9. `event_gene_unlimited` — Unlimited Event Genes

- Matches all rows containing `"item_category":18` with `limit_type=1` and
  `limit_max` 100/999.
- Replaces them with `"limit_type":255,"limit_max":9` (exact 30-byte match).
  `limit_type=255` is the catalog's no-limit sentinel; `limit_max=9` is ignored
  for that sentinel and keeps the JSON length stable. The previous `-1/-1`
  replacement could leave the item blocked after a large first purchase.
- Reference count: **33** rows.
- The catalog contains other gene rows in the Guild/Ancient/Unknown Paradise
  shops with limits 10/98/20; this option intentionally targets the Event Shop
  gene rows (100/999).

#### 10. `flask_3h` — Mana Stone Compactor 3h Recharge

- Sets the Mana Stone Compactor's three 7,200s sites (`0xA63904`, `0xA6390C`,
  `0xA6649C`) to 10,800s (3h); the Gold Cylinder stays at 21,600s (6h).
- **Always-active bypass removed:** the 2.5.x branch at `0xA655C8` jumped
  directly to the success path at `0xA655E4`, making laboratory tools usable at
  any time. The original `cmp w22, #2` is restored so the normal cooldown and
  use-count checks run again.
- **Energy Flask windows are no longer rewritten.** The historical 8-window
  `laboratorytimezone.unity3d` rewrite was removed in 2.5.6: the server's
  window guard only accepts 12-15h and 18-21h, so the extra client windows
  (15-18h and 21-24h) produced free-but-discarded collections and an infinite
  use bug. The original two windows are kept.

#### 10b. `energy_flask_x10` — Energy Flask x10 Stamina

- `laboratory_use_fields` (`0xA64D88`) grants the daily Energy Flask's free
  stamina after reading the current `stamina` from the state. Site `0xA65648`
  is `add x0, x19, #0x64` (`60920191`, +100); the option rewrites it to
  `add x0, x19, #0x3e8` (`60a20f91`, +1,000) before the native
  `set_top_level_value("stamina")` call.
- The grant stays inside the native window guard, so the flask is still limited
  to the 12-15h and 18-21h windows and the use count increments once per
  window.
- Reference count: **1** changed instruction.

#### 11. `gold_cylinder_fix` — Gold Flask 6h

- Sites:
  - `0xA63708`: `mov w8, #21600` (`528A8C08`);
  - `0xA6517C`: `mov w9, #21600` (`528A8C09`);
  - `0xA651E8`: `mov w8, #21600` (`528A8C08`);
  - `0xA653DC`: `mov w2, #21600` (`528A8C02`).
- Accepts both the original value and the legacy `#10800` (`528546xx`), restoring 21,600s.
- The legacy flask patch modified these four sites, which caused the Gold
  Cylinder to show 50% after collection.

#### 12. `event_coin_x10` — 10x Event Coin

- Hooks the common return path at `0x8D05C0` (`mov x0, x19`), jumping to cave `0xB333CC`:
  - `mov w8, #10`;
  - `mul x19, x19, x8`;
  - `mov x0, x19`;
  - branch back to `0x8D05C4`.
- Restores the legacy hook site at `0x8D05B8` (string-cleanup branch) to `b 0x8D05C0`
  (`02000014`).

#### 13. `guild_raid_score_fix` — Guild Raid 64-bit

- Start site `0x831CE4`: original `1f0000f100c09f9a` → branch to sentinel cave
  `0xB335C4` + NOP.
- Installer `0xAB00D8`: original `a1150094` → branch to client cave `0xB33424`.
- Client RVAs: normal `0x158C744`, practice `0x158CF94`.
- The client cave restores the true 64-bit value from `rank_list[0].rank_score`
  before calling `set_scoreLimit`.
- Reference count: **2**.

#### 14. `single_black_hammer` — 1 Black Hammer

- Site `0x8A7404`, function `EquipmentTranscendStateAccess::transcend`.
- Original: `sub x22, x8, #0xe` (`163900d1`) → `mov w22, #1` (`36008052`).
- Item `130006` cost for levels 15–19 is fixed to 1 instead of `level - 14`.

#### Equipment tier completion — `equipment_tier_upgrades`

- Item-based transcendence advances +10..+14 to +15, +15..+19 to +20 and +20..+25 to +26. One appropriate hammer is consumed; existing gold and eligibility checks still apply.
- The success mutation at `0xA188BC` branches to `0xB2A700`; the runtime client installer at `0xAB3394` uses `0xB2A800` for confirmation, stat preview, selection refresh and hammer-count checks. Original bytes and cave hashes are validated before mutation.
- The option also enables the existing single-black-hammer cost and high-tier success rules. They remain independently selectable.

#### 15. `single_gem_fang` — 1 Dragon Fang Opens All 3 Gem Slots

- Site `0x7F5148`, `REQ_EQUIPMENT_SET_HOLE` path: `csinc x24, x9, xzr, ne` (`38159f9a`) → `mov x24, #1` (`380080d2`).
- Item `2060051`; opening any locked gem slot consumes 1 Dragon Fang.
- All-holes cave `0xB2AD10` (hooked at `0x8ADE80` inside `GemStateAccess::mutate_equipment_hole`): calls `update_equipment_hole_json` (`0xA19EF0`) for `hole_pos` `1`, `2`, and `3`, preserving any already-open hole's `gem_code_attr`.

#### 16. `select_all_4_5` — Select All 4★/5★

- Installer `0xAB0118` (second `patch_words` call in
  `patch_offline_convenience_flow`):
  - original `bl 0xAB575C` (`91150094`) → branch to cave `0xB33634`.
- The cave now performs three operations:
  1. the original `patch_words` call;
  2. a 16-byte client hook at `0x1CE93F8`
     (`EquipmentMenuGUI::BlockSelect`, start `0x1CE9214`, offset `0x1E4`);
  3. a second `patch_words` call at `0x1CE9420` that replaces the quality
     load with `mov w11, #3`, routing quality-4/5 items into the Epic bucket.
- Grade logic: if `gradeChecked[3]` (Select All) is set and equipment grade is
  4 or 5, rewrites the grade to 3 and the bucket index to 3; when Select All is
  unchecked, original filtering is preserved.
- The 108-byte grade stub moved to the free cave tail at `0xB337B4` so the
  installer can hold the second patch call.
- Validated by SHA-256 of the cave slot and installer site; disjoint from the
  Guild Raid cave (`0xB33610`).
- **Runtime validated (2026-11-08):** Multi Extraction removed four 5★ items
  (`02045535`, `01035426`, `02065423`, `03095428`), all with quality 4/5. The
  run stopped at four because the Alchemy gauge filled.

#### 17. `limit_break_gold_half` — 50% Limit Break Gold

- Table `kFwtCreatureLimitBreakCosts` at `0x756CF0`, 45 rows × 24 bytes.
- Halves only the `gold_cost` field at `+20`.
- Material codes `210001`/`210002` and counts remain untouched.
- Validated via original/patched table SHA-256.
- Reference count: **45**.

#### 18. `coocoo_exp_x2` — Coocoo EXP x2

- Site `0x7FCF30`, `SUMEXP_CREATURE` handler.
- Original: `cset w8, eq` (`e8179f1a`) → `mov w8, #1` (`28008052`).
- Keeps the 2x EXP multiplier active for any EXP material.

#### 19. `stamina_cost_half` — 50% Dungeon Stamina (default in `--all`)

- Site `0x8D744C`, `BattleSecondStartStateAccess::charge`:
  - original `sub x0, x27, x28` (`60031ccb`) →
    `sub x0, x27, x28, lsr #1` (`60075ccb`).
- **Current default:** `--all` enables this mode (server-side half debit). Client
  UI/validation still uses the full table cost, so the client may require full
  stamina to enter and display the full number. Use `--stamina-cost-half`
  explicitly outside `--all`; never combine with `--stamina-cashback`.

#### 20. `stamina_potion_1000` — Stamina Potion 1000

- Function `StaminaItemStateAccess::use_potion` (`0x8EBE80`), normal branch:
  - `int_field("max_stamina", default 1)` → `x21`;
  - `int_field("stamina", default 0)` → `x23`;
  - `add x0, x23, x21` at `0x8EC258` → `to_string` → `set_top_level_value("stamina")`.
- Patch at `0x8EC1E8`:
  - original `csinc x21, x0, xzr, gt` (`15c49f9a`);
  - replacement `mov x21, #1000` (`157d80d2`).
- Effect: normal stamina potions add 1,000 points instead of `max_stamina`.
- Reference count: **1**; unit and inspector tests implemented.
- **Runtime validated on 2026-11-07:** using a normal stamina potion granted
  1,000 stamina in-game on the MuMu `.120` instance.

#### 21. `lan_redirect` — LAN Redirect

- Shim at `0xAB6858` (max `0xAB7650 - 0xAB6858 = 0xDF8` bytes), magic `FLAN`.
- Sites:
  - `0xAAD9F8` boundary hook;
  - `0xAA6D70` loopback connect stub;
  - `0xAB5D48` server ready check;
  - `0xAAE450` socket reaper → `ret`;
  - `0xAADE84`, `0xAADFA0` attendance/shop materializers → `mov w0, #1`;
  - server spawn `BL`s → `NOP`.
- DEX: `0x006148` (4 bytes) and `0x005D7C` (6 bytes) zeroed to skip local save
  backup dialogs; DEX checksums recomputed.

#### 22. `stamina_cashback` — 50% Cashback (removed in 2.5.35; historical)

- **Status:** removed in 2.5.35 (companion script deleted; `PatchOptions.stamina_cashback` remains an internal blocked stub for backwards compatibility). `--all` uses `stamina_cost_half` (server-side half debit). The client still required full stamina to enter, and the host companion attempted to refund half the cost after the battle finished.
- **Former companion** (removed in 2.5.35):
  - polled `pending_battles` from the save via ADB;
  - tracked `cost`, `stamina_charged`, and baseline stamina;
  - detected `rewarded=True` or battle removal and sent
    `UPDATE_STAMINA_TIME` (`stamina = current + cost//2`) to the local server via
    `adb forward tcp:18010 tcp:8010`;
  - verified whether the server persisted the new stamina; if not, marked
    `refund_failed` instead of reporting a false success.
- **Live test on 2026-11-07:** battle `6820155` (Foose-11, cost 4) completed on
  the test emulator. The companion detected `charged at stamina=539` and sent a
  refund of 2, but the embedded server replied `left_stamina=539` and both the
  save and API remained at 539. The false-refund log is archived in
  `backups/cashback.false-refund.log`.
- **Root cause:** the stock `libfwt_local_server.so` treats `UPDATE_STAMINA_TIME`
  as **read-only**: `fwt::handle_update_stamina_time` only formats the response
  using current `stamina`, `max_stamina`, and `left_seconds` without writing the
  incoming `stamina` field. (A separate research reimplementation of the server has a
  writable `stamina` handler, but that is not the binary embedded in the APK.)
- **Without modifying the client:** the companion uses stdlib and talks to the
  local server without touching `libil2cpp.so`. Persisting a post-battle refund
  would require a server-side binary patch (e.g., in the battle result handler).
- **Current default:** `stamina_cost_half` is used by `--all`; never combine both
  flags.

#### 23. `campaign_shop_discount` — 90% Campaign Shop Discount

- Applies a 90% discount (`ceil(price * 0.1)`, minimum 1) across all campaign shops:
  - Battle of Honor Shop (`shop_content: 1`, 16 items)
  - Guild Raid Shop (`shop_content: 3`, 14 items)
  - Ancient Coins Shop (`shop_content: 5`, 23 items)
  - Unknown Paradise Shop (`shop_content: 6`, 16 items)
  - Friend Shop (`friend_point` rows, 25 items)
- The server patch also discounts nine valid `shop_kind: 6` rows using
  `price_coin`. The `6A102` item is assembled from multiple string fragments;
  its first fragment ends in `price_coin:20`, while the running server reports
  20,000. The patch changes that two-character fragment to ` 2` so the assembled
  number becomes 2,000. This gives 104 matched fields/fragments. A temporary
  server-library test on the emulator confirmed `GET_SHOP_LIST` reports 1,500,
  1,750 and 2,000 for `69974`, `6A101` and `6A102`; the original library was
  restored and hash verified afterward. Actual debit remains untested.
- The Ancient Coins rows use `price_code` (`200001`/`200002`/`200003`) plus
  `price_count`; the server purchase handler reads the patched `price_count`,
  so the actual debit is discounted as well as the list price. Verified with
  `SHOP_BUY_CONTENTS` `5209`: 900,000 -> 90,000 gold.
- Exact byte length preservation with whitespace padding ensures binary stability and idempotency.
- The width-preserving leading space is the idempotence marker: a second pass
  leaves the already-discounted table untouched.

#### 24. `mode_drops_x10` — 10x Mode Drops (6 Game Modes)

- Multiplies drops and rewards by 10x across 6 distinct offline game modes:
  1. **Unknown Paradise**: Final cycle-end rank and grade rewards (reward types
     1, 2, and 3 in `kWorldBossCycleRewardRows` at `0x75EB90`, 22 rows, plus
     the matching rows in all 7 `worldbossreward*.unity3d` client datatables)
     are multiplied by 10x. Daily settlement mana stones (`28,800`) and
     Day 5/6/7 boxes remain 1x; instead, the daily Kraken Scale cave
     (`0x8E69F4` -> `0xB2AB00`) grants a fixed **500 Kraken Scales per fight**
     (`500 + 500 = 1000/day`) directly to inventory and writes
     FirstClearRewardPayload.reward_item` so Days 1-4 and 2nd attacks show the
     reward instead of a blank box. The event `10002` row at `0x75F6C0` is kept
     as stock `row_type == 2` so `WORLDBOSS_RESULT_EVENT` opens the Mobile Repair
     Shop (`Instant Repair`).
  2. **Battle of Honor**: the embedded result handler now grants and displays
     **60** Honor Coins per PvP win (`0x83FCF0`, `mov w27,#6` -> `#60`).
     The `honorreward.unity3d` preview asset is patched too.
     - **Rank points fixed at 100**: the return of `pvp_score_delta` at `0x95563C`
       branches to cave `0xB33838`, which sets the score delta to 100 when
       the win flag is set. Losses are unchanged.
  3. **Dimension Breakthrough**: match-win gold/item roll multiplier trampoline
     cave at `0x94B528` -> `0xB33408`; the gene chance gate at `0x83C1E4` is
     bypassed and the rolled gene count at `0x83C25C` is multiplied by 10 via
     the `0xB337A4` cave.
  4. **Pit of Nephthys**: All 126 stages (prefixes `0x70`, `0x71`) base gold
     reward multiplied by 10x in the dungeon reward table. Item/mana/gene
     drops are multiplied by the extended campaign item trampoline
     (`0xA2D0D4`/`0xA2D6C4` -> `0xB33734`), which recognizes prefixes
     `0x10-0x12`, `0x70-0x71` and `0x80-0x81`. The item trampoline belongs to
     `campaign_gold`, so `--all` (which enables both) is required for the
     Nephthys item multiplier.
  5. **Sky Library**: All 156 riddle rows in `kFwtRiddleRewardRows` reward quantity (column 5) multiplied by 10x.
  6. **Lost Island**: All 82 stages (prefixes `0x80`, `0x81`) base gold reward
     multiplied by 10x; item drops use the same extended item trampoline.
- Total modifications: **392** sites and table entries (22 final rank/grade
  World Boss rows, fixed daily Kraken Scale hook, gold
  table/riddle/dimension/honor/gene/rank-point hook; event `10002` at `0x75F6C0`
  stays stock `row_type == 2`); the Nephthys/Lost Island item trampoline is
  installed by `campaign_gold`.

#### 25. `battle_arena_fix` - Battle Arena Team Configuration Save Fix

- Fixes the bug where configuring Battle Arena/PvP teams (4 groups of 2
  players each) failed to save.
- Week-state and empty-slot sites:
  - `0x95C698`: Week state check bypass (`tbz w0, #0` -> `mov w0, #1; nop`)
  - `0x95C750`: Week state branch bypass (`b.ne` -> `nop`)
  - `0x95CAB0`: Arena week transition verification bypass (`tbz w0, #0` -> `mov w0, #1; nop`)
  - `0x8B5288`: Empty slot validation handling (`cbz x21` -> `mov x21, xzr; nop`)
- The client sends the four teams as eight member IDs, while the offline
  server stores four team leaders. Two compaction caves handle this:
  - `REQ_REGISTER_PVP` hook `0x83A384` -> cave `0xAC81B0`: if the vector has
    eight values, copy indices 0/2/4/6 to 0/1/2/3 and set the length to four;
    then resume the native 32-byte check at `0x83A398` (or fail at `0x83AF54`).
  - `SET_DEFENSE_TEAM_PVP` hook `0x83A21C` -> cave `0xAC8200`: same compaction
    for the defense vector at `[sp+0x18a0]`, resuming at `0x83A224`.
- Total modifications: **8 sites** (3 week-state + 1 empty slot + 2 PvP
  compaction hooks + 2 caves).

#### 25b. `battle_arena_save_fix` — Battle Arena Team Save (client hook)

- **Cause**: `ArenaAttackTeamListGUIInInventory.Init` (client RVA `0x1AA6F50`)
  stores its team manager at `+0x60` only when the IL2CPP type-hierarchy check
  passes; a mismatch stores NULL (`csel x8, x20, xzr, eq` at RVA `0x1AA6FCC`).
  `OnOKButtonPressed` (`0x1AA83C4`) then calls `CheckValidityOfModifiedAttackTeam`
  (`0x1AA81F8`), whose NULL load throws a `NullReferenceException` swallowed by
  Unity, so the Save button silently does nothing.
- **Post-covault hook**: instead of patching client memory during early startup
  (before AppSealing finalizes permissions), `0xAB337C` (epilogue of the
  covault permission-finalization function, original `add sp, sp, #0xc50`)
  branches to cave `0xB33634`.
- The cave reads the cached `libil2cpp.so` base from server global `0xBE3798`
  and calls `patch_words` to rewrite client RVA `0x01AA6FCC` from `88029f9a`
  (`csel x8, x20, xzr, eq`) to `e80314aa` (`mov x8, x20`).
- **Mutual exclusion**: `0xB33634` occupies the shared `0xF0`-byte client cave
  slot (`0xB33634..0xB33724`) alongside the `guild_raid_mercenary` client tail,
  so `battle_arena_save_fix` is mutually exclusive with `select_all_4_5`
  (which overwrites the full `0xF0` slot).
- **Idempotence & reference count**: accepts original or patched hook/cave;
  returns **1** when either cave or hook changes, 0 when already applied.

#### 26. `guild_raid_mercenary` — Guild Raid Self-Mercenary Selection

- In offline play, guild friends are unavailable. The first anti-self-hire check
  in `guild_battle_hired_projection` (`0x930100`, `b.eq 0x9302c4`, `200e0054`) is
  redirected to the self-projection cave (`0xB34860`, **1,144 bytes** carved inside
  `itanium_demangle::AbstractManglingParser::parseUnnamedTypeName`), returning to epilogue `0x9302BC` (sets
  valid flag) or falling through to `0x930104` when non-self.
- **Weekday mercenary projection**: reads `<weekday>_crs_idx` from
  `guild_hired_soldier_info` (weekday resolved from `server_now_epoch`) and filters the player's `creatures`, `costumes`,
  `equipments`, `runes`, and `soulgears` by `crs_idx` to populate all 7
  `GuildBattleHiredProjection` slots. Missing costumes retain JSON `null`; a
  missing or invalid configured hero resumes the stock path for the selected
  guild member. Socketed gem bonuses remain under investigation.
- **Client filter removal**: post-covault hook `0xAB3380` jumps to a **68-byte**
  client cave at `0xB336D8` (tail of the shared `0xF0`-byte `0xB33634` slot),
  patching client RVA `0x1EE5220` so the player appears in the selectable Guild
  Raid mercenary list.
- Because the 68-byte client cave occupies the tail of `0xB33634`,
  `guild_raid_mercenary` remains mutually exclusive with `select_all_4_5`.
- Reference count: **4** changed items (2 caves + 2 hooks).

#### 27. `event_limits_daily` — Daily Event Shop Limits

- Every shop row with `"limit_type":3` (the client's "Lifely" period, which
  never resets) is changed to `"limit_type":1` (daily). **Every**
  `"limit_type":4` row (event/Honor period) is converted too, so every
  event-purchase restriction resets after 24 hours.
- `limit_max` is preserved, so gem-upgrade materials that were limited to 3
  per event become 3 per day and are purchasable again after the daily reset.
- Replacement is byte-length preserving (`"limit_type":3` -> `"limit_type":1`;
  the type-4 replacement changes only the final digit).
- Reference count: **1,423** occurrences (1,224 `limit_type=3` rows plus 199
  `limit_type=4` rows).
- The lifetime `shop_buy_counts` counter is hooked at `0x88091C` for event-shop
  codes (`699xx`/`703xx`): the lookup returns 0, so a row bought before the
  period change is not stuck at "limit reached". Other shops keep their
  original counters.
- Includes Event Shop limited-edition items and event-limited campaign-shop
  rows. Monthly (`limit_type=2`) rows outside the Event Shop are untouched.

#### 28. `no_equip_drops` — Remove Equipment Drops

- The 35-int stage row stores `_rewardEquipChance` at index 10 and
  `_rewardEquipTable` at index 11.
- For every one of the **431** stages with a positive equipment chance, the
  equipment chance is set to `0`.
- Its weight is distributed proportionally (largest-remainder integer
  apportionment) across the other eligible categories in the same row:
  gold (4), item (26, requires table 28 > 0), monster (14, requires table 16),
  manastone (7), gene (22, requires id 23 >= 0) and energy (31, requires
  value 32 >= 0). Per-row total drop weight is preserved.
- This changes the server's weighted drop pool, not the client stage preview.

#### 29. `recycle_hammer_rewards` - Recycling Gives Transcendence Tickets (experimental)

- Not enabled by `--all` (2.5.9); mutually exclusive with `recycle_six_star`.
- The 2.5.8 fix makes the completion trampoline return through `0x89D154` so
  the granted ticket is published in the response; it still needs runtime
  validation.

- The native alchemy path picks an equipment reward from
  `kFwtEquipRewardRows` at `0x639760`. The pick is not reliable in the offline
  server, so the replacement does not depend on the reward tables.
- **Grade capture** at `0x89CCD0` -> cave `0xAC8240`: loads the real 1..5
  equipment grade (`ldr w28, [x0, #0x38]`) and saves it to `[0xBE2F14]` before
  the handler overwrites `x28` with the reward-string length.
- **Reward pick wrapper** at `0x9A3240` -> cave `0xAC8290`: when the shared
  `pick_valid_battle_equip_reward` failure path is reached from the disassemble
  caller (`0x89D084`), it writes a valid dummy row at `x28` and returns
  success; other callers still receive the original failure.
- **Selector trampoline** at `0x89CEF8` -> cave `0xB33820`: saves the native
  table selector (`w21`: `0x65` normal, `0x6A` final) to `[0xBE2CBC]`, executes
  the original `add w22, w21, w28`, and resumes at `0x89CEFC`.
- **Completion trampoline** at `0x89D150` -> cave `0xB333A0`: builds `13000X`,
  where `X` is the captured grade (1-5) for normal completions or `6` when the
  selector is `0x6A`. It calls `grant_item_json` with the **native ItemInfo
  slot** (`sp+0x1e0`) and returns to `0x89D154`, so the native response append
  (`state+0x100`) publishes the ticket to the client. Only the
  `grant_equipment_json` call is replaced; 2.5.8 fixed the previous jump to
  `0x89D238`, which skipped the append and kept the ticket out of the response.
- Normal bar completion awards **130001-130005** (class I-V equipment
  transcendence tickets); the final/full-bar step awards **130006** (Ultimate
  Transcendence Ticket, the black +16..+20 hammer).
- The previous 102..111 reward-table fill was removed because the runtime
  alchemy groups are `101 + reward-string length` (observed 129, 131, 143) in
  the `{_weightNo, _weightValue, _equipCode}` table; filling 102..111 corrupted
  unrelated rewards and caused the Select All error.
- Reference count: **5 caves + 4 hooks = 9** changed sites.

#### 29b. `recycle_six_star` - Recycling Grants 6★ Equipment (default)

- The native completion pick (`pick_valid_battle_equip_reward`, `0x9A2FB8`)
  selects a row from `kFwtEquipRewardRows` using the runtime selector
  `w21 + w28` = `0x65 + grade` (102-106, normal) or `0x6A + grade`
  (107-111, final). The table lives in `.rodata` at `0x639760` (vaddr == file
  offset) and has 13,011 rows of `{_weightNo, _weightValue, _equipCode}`
  (12 bytes each); the ten alchemy groups hold **873** rows.
- The option rewrites only `_equipCode` (row offset `+8`) to **16864643**
  (`Absolute Gavel of Defense`, grade 5, `_secretegrade` 3 — the 6★ tier) for
  every row in groups 102-111, in both the server table and the client assets
  `equipreward.unity3d` / `equiprewardjapan.unity3d`.
- Because the native grant still runs, the equipment grant, the response
  append and the alchemy point accounting are unchanged.
- Reference count: **873** rows. Idempotent (already-patched rows are skipped).
- **Equal set chances (2.5.25).** The vanilla `_weightValue` column gave four
  sets up to ~31x the weight of the rest. Both `_weightValue` (+4) and
  `_equipCode` (+8) are now rewritten in the server table and in
  `equipreward.unity3d`: each group's original total weight is split equally
  across the sets of its slot (difference ≤ 1 unit), and each set's total is
  spread evenly over the rows assigned to it. The group row order and the
  total weight are preserved, so a second pass is a no-op.
- **Slot-matched 6★ pools (2.5.14).** The obtainable 6★ sets come from the
  `equipselectlist` **list 10009** (the 6★ set selection ticket granted by the
  summon mileage): **66 sets / 198 pieces**. Hero-exclusive sets
  (`setitemtable` `_setPreconditionid == 101`, e.g. "Deimos only") are excluded;
  class-restricted sets (62-69) remain. Each list piece is mapped to its
  quality-5 counterpart (golden six-star display) and split by `_equipGrade`
  (slot): 36/45/39/42/36 pieces for slots 1..5. Group `0x65+N` / `0x6A+N`
  receives the slot-N pool, so the bar of slot N always rolls a six-star piece
  of that slot (weapon/shield/accessory random).
- A slot-matched variant (cave `0x89D088` + pool `0xB333C4`) was prototyped in
  2.5.10, but the alchemy reward is resolved by the **client** when it opens the
  capsule (`reward_capsule` + the client `equipreward` table), so the
  server-side cave does not influence it.

#### 30. `upgrade_no_fail_above_20` — No Upgrade Failure Above +20

- Server table `0x6BAE64`, six int32 values for the infinite-transcend path:
  `100, 90, 80, 70, 60, 50` for current levels 20..25.
- Every entry becomes `100`; the failure branch and the insurance-card
  regression path are never reached. Reference count: **5** changed entries
  (level 20 was already 100%).

#### 31. `limit_break_cost_half` — 50% Limit Break Cost (Gold + Fruit)

- `kFwtCreatureLimitBreakCosts` at `0x756CF0`, 45 rows × 24 bytes:
  level, next level, item category, item code, item count, gold cost.
- Both the material count (`+16`) and gold cost (`+20`) are divided by two.
  Covers Unknown Fruit (`0x210001`) and Balance Jade (`0x210002`) rows.
- Mutually exclusive with the legacy `limit_break_gold_half` option.
- Reference count: **45** rows.

#### 32. `devil_boost_x10` — 10x Devil's Soul EXP Boost

- The EXP-synthesis handler detects a Devil's Soul ingredient and multiplies
  the summed ingredient EXP by the float at `0x6C49D8` (native value `2.0`).
- The option changes that float to `20.0`, so the Devil's Soul boost itself is
  ten times stronger (2x -> 20x).
- Reference count: **1** float.
- Mutually independent from `mode_drops_x10`.

#### 33. `sacred_lands_restore` — Restore Sacred Lands Set

- Set group `4028` ("Sacred Lands", support-only, slot IV) shipped with
  `_itemGrade: 1` in every localized `SetItemTable` bundle even though all of
  its `EquipTable` pieces are `_equipGrade: 4`. Grade-based filters therefore
  hid it from the grade-4 rotation and the set selection ticket UI.
- The asset pass rewrites both 4028 rows to `_itemGrade: 4` in
  `setitemtable.unity3d`, `setitemtablechinese.unity3d`,
  `setitemtableenglish.unity3d` and `setitemtablejapanese.unity3d` (the other
  locales fall back to the base table and contain no 4028 rows).
- `equipselectlist.unity3d` gains `(10001, 4028)` and `(10004, 4028)` for the
  ★4 Event/Set selection tickets.
- The bootstrap independently verifies `equipselectlist.unity3d` against the
  hardcoded DEX hash `A6AE3829…`; the build recomputes it and replaces the
  constant in `FwtResourceBootstrapActivity.smali` (17 contract edits instead
  of 16).
- Runtime validation: the installed device datatables report grade `[4, 4]`
  and both ticket rows, and the resource bootstrap accepts the patched bundle.
- Rotation already contains the pair `(4028, 4101)` in
  `fwt_six_star_rotation_pairs`; no rotation table change is needed.

#### 34. `coocoo_level_x2` — Coocoo Garden / Pit of Nephthys Level x2

- The 30 coocoo reward stages live in the contiguous stage table at `0x735488`
  (rows `700010`–`700100`, `701010`–`701100` and `702010`–`702100`, 140 bytes
  each). The exp-creature level is stored as two int32 at row offsets
  `+68`/`+72`.
- The 702xxx tier is the Pit of Nephthys tier. It uses monster `00230841`
  instead of `00210841`/`00220841` but the same level ladder. Leaving it
  untouched made the post-reset reward fall back to level 220, because the
  reset path uses the 702 row rather than the 700/701 rows.
- The option doubles those two fields for every row (2→4, 4→8, …, 220→440).
  The final stage of every tier therefore drops four level-440 coocoos instead
  of four level-220 coocoos, compensating for the fixed four-creature reward
  that the 10x item multiplier cannot touch.
- Expected rows: **30**. The patch is idempotent: a second pass leaves already
  doubled rows untouched.
- Runtime validation (2.5.0): Rock Coocoo's Garden 10 result screen shows four
  level-440 coocoos, and the save contains four `00210841` monsters at level
  440 (`mon_idx` 1370–1373). 2.5.5 extends the same doubling to the 702 tier,
  which is the table used after the Pit of Nephthys reset.

#### 35. `ship_parts_90_off` — 90% Off Battleship Parts

- `worldboss_ship_part_gold_cost` (`0x977FB8`) indexes three int64 arrays in
  `.rodata`: common costs at `0x75F790` (30 values), part-5 costs at
  `0x75F880` (10 values), and part-7 costs at `0x75F950` (4 values, last is
  padding). The level cap table is at `0x75F768`.
- The option applies `ceil(cost * 0.1)` to all **41** non-zero values. The
  server charges the discounted gold in `WORLDBOSS_SHIP_PART_LEVELUP`; the
  client does not embed a copy of these costs. The patch is idempotent and
  reports 41 changes on the reference build.
- Runtime validation (2.5.5): upgrading part 1 from level 1 to 2 charges 500
  gold (original first-step cost 5,000), while the padding entries stay zero.
- Renamed from `ship_parts_half` (when it originally halved costs in 2.5.4);
  `--ship-parts-half` and `apply_ship_parts_half` are kept as compatibility aliases.

#### 06.10. `worldboss_full_ship_repair` — Unknown Paradise Full Ship Repair

- Timed repair sets the post-tick HP to the calculated maximum at `0x976048`, after the stock first repair interval.
- Instant Repair uses a full-bar repair amount at `0x849D60`. The stock HP setter clamps the sum to maximum HP.
- Revive uses 100% of maximum HP at `0x97704C`. The inspector requires all three native replacements.
- Battle damage settlement, repair eligibility, and payment retain their stock behavior.

#### 36. `crystal_skill_90_off` — 90% Off Core Crystal Upgrades

- `WORLDBOSS_SHIP_SKILL_LEVELUP` charges hard-coded 50 Kraken Scales
  (`280001`) per crystal skill level. Site `0x84A2C0` (`mov w2, #0x32`,
  `42068052`) becomes `mov w2, #5` (`a2008052`).
- The client `files/Resources/datatable/crystalskillcost.unity3d` table has 29
  rows × 3 costs (`_crsCost1/2/3`), all 50. The build rewrites all 87 fields to
  5 so the Core Processing Plant UI displays the discounted price and the
  client pre-check matches the server charge. The resource contract is
  recomputed and written into the bootstrap DEX in the same build.
- Runtime validation (2.5.0): upgrading skill 1 from level 1 to 2 deducted 5
  Kraken Scales (`280001` count 590 → 585) and returned `skill_level_01: 2`.

#### 37. `gem_mining_x10` - Gems x10 (Mining)

- `GemMiningStateAccess::mine` (`0x8AAC80`) calls `change_gem_count_json` with a
  hard-coded count of 1 at `0x8AB110` (`mov w2, #1`).
- The site branches to cave `0xB33830`, which executes `mov w2, #10` and
  returns to `0x8AB114`.
- Every gem-mining roll, including the 20-crystal paid roll, awards 10 gems of
  the same rolled type.
- Reference count: **1** hook.

#### 38. `gem_mining_types` - Gem Type Restriction

- `GemMiningStateAccess::mine` selects a random entry from the nine level-1
  gem codes (`16781` .. `96781`, attributes 1..9) at `0xBA8478`.
- Hook `0x8AB08C` -> cave `0xAC8260`: replaces the random index with
  `allowed[random % 5]`, where `allowed = [1, 5, 6, 7, 8]` (zero-based). This
  restricts the roll to attributes **2 (MP), 6 (Counter Rate), 7 (Counter
  Damage), 8 (Dodge) and 9 (Hit Rate)**.
- HP/ATK/DEF/CRIT (attributes 1/3/4/5) are excluded because they are already
  sold as level-6 gems in the Special Beginner Package.
- Reference count: **1 hook + 1 cave = 2** changed sites.

#### 39. `gem_upgrade_gold_half` - 50% Off Gem Upgrade Gold

- `GemStateAccess::graft` (`0x8AC944`) receives the client-calculated
  `fee_gold` and subtracts it from the lord's gold at `0x8ACA6C`
  (`sub x0, x22, x26`).
- The option replaces that instruction with
  `sub x0, x22, x26, lsr #1` (`c0 06 5a cb`), so the actual debit is half of
  the requested fee. The duplicate/consumable gem cost is not touched.
- The client still displays the original fee before the request, but the
  response `info_lord.gold` and the server state reflect the halved charge.
- Reference count: **1** instruction site. The patch is idempotent because it
  accepts either the original or the replacement encoding.

#### 39b. `gem_level6` - Gems Level 6

- The lobby gem table at `0xBA8478` holds nine 16-byte entries whose pointers
  resolve (through `R_AARCH64_RELATIVE` relocations) to the level-1 gem code
  strings `"16781"` .. `"96781"` (attributes 1..9). The gem **level is the last
  digit** of the code, so the patch rewrites that digit from `1` to `6`, turning
  the codes into `"16786"` .. `"96786"` (same attribute, level 6).
- Nine single-byte `.rodata` edits at `0x21BD6F`, `0x4D4F78`, `0x499897`,
  `0x5FE5E8`, `0x3B2D83`, `0x2A3B7E`, `0x41516C`, `0x546E6C`, `0x505EC3`
  (offset +4 of each string). Both the mined gems and the 20-crystal paid roll
  read this table, so every gem obtained or bought in the lobby gem screen is
  level 6 while the attribute stays the same.
- Verification: **9** changed bytes on the first pass, 0 on the second.

#### 40. `guild_raid_reward_x10` — Guild Raid Rank Rewards x10

- The weekly settlement mails the daily and weekly guild-raid rank rewards from
  two 8-entry tables in `.rodata` (vaddr == file offset for this region):
  - daily: `0x758260`, 8 entries;
  - weekly: `0x7583A0`, 8 entries.
- Each entry is `0x28` bytes: reward id at `+0x00` and three int32 amounts at
  `+0x18` (item `150001`), `+0x1c` (gold) and `+0x20` (secondary item). The
  reference values are shipped in `GUILD_RAID_DAILY_REWARDS` /
  `GUILD_RAID_WEEKLY_REWARDS` and act as version guards.
- Every non-zero amount is multiplied by 10; padding and reward ids are left
  untouched. The patch is idempotent (accepts original or x10 values).
- Reference count: **32** amounts (8 daily + 24 weekly).
- Scope: the per-attack score reward (gacha box from `guildraidreward.unity3d`)
  and the per-boss reward flow are not touched.

#### 40b. `option_max_attributes` — Max Quality on Every Option Roll

- `weighted_randoption_id_json` (`0x9A2790`) draws inside a pool of rows that
  share an attribute key (`row + 4`) and an equipment grade (whose column of
  six weights applies). A parallel table at `0x634060` (12 bytes per row:
  option id, quality grade 1–5, combat power) ranks each pool's rows, and the
  picker's `:mastery-good-pick` path prefers the best grade.
- The patch leaves only the best-grade row(s) of each pool weighted and hands
  them the pool's whole weight, so each attribute keeps the odds it had while
  the value inside it becomes the maximum available. Measured on the reference
  library: **180 pools** (attribute × grade), every one with a grade-5 candidate,
  and all 1,856 rows rewritten (the sub-max rows lose their weight).
- It rewrites **table weights only** (`fwt_randoption_rows`, `0x621E60`,
  1,856 rows × 40 bytes). The candidate list built for locks is untouched, so
  locked attributes stay excluded and locked values are restored as stock.
- The old quality-bias words at `0xA16FEC`/`0xA16FF0` stay stock on purpose:
  that path (`mov w3,#1`, `mov w4,#450`) only raises the odds of taking
  `:mastery-good-pick`, which bypasses locked attributes (see 41).
- Idempotent: a second pass reports 0 rows changed and the inspector verifies
  structurally that no sub-max row keeps weight.

#### 41. `equipment_option_factor` — Equipment Option Mastery Bias Factor

- `weighted_randoption_id_json` (`0x9A2790`) turns the passed mastery bonus
  into a `1/10000` probability (`num = total * bonus + den - 1`,
  `q = min(10000, num / den)`).
- When `equipment_option_factor > 0` (`bonus = min(10000, 450 * factor)`), both
  reads of the incoming bonus argument are replaced directly with `movz`
  constants:
  - `0x9A2AF4` (`ldr w8, [sp, #0xc]`) -> `movz w8, #<bonus>`
  - `0x9A2B14` (`ldr w9, [sp, #0xc]`) -> `movz w9, #<bonus>`
- Covers option potions, granted gear, and re-rolls uniformly.
- **Known limitation (locked options):** the caller gate cave previously placed
  at `0xB39860`/`0xB39874` was removed because `[x29, #-0x38]` did not hold the
  locked-option set. High bonus factors frequently take `:mastery-good-pick`
  (`0x9A2C98`), which bypasses locked attributes. Consequently,
  `equipment_option_factor` defaults to `0` (disabled) in both GUI and CLI; use
  `equipment_lock_fix` without a boost when preserving locks matters.
- Reference count: **2** sites when `factor > 0` (0 when `factor == 0`).

#### 42. `equipment_lock_fix` — Locked Options Survive the First Roll

- `EquipmentStateAccess::change_option` (`0xA1832C`) previously called
  `refresh_equipment_options_for_code_json` (`0xA16FB8`) with an empty lock set
  before reading `lock_list` and rolling again, overwriting the saved record
  used to restore locked lines (10 lock violations in 17 lock-change
  transitions on device).
- NOPs `0xA18354` (`bl refresh_equipment_options_for_code_json` -> `nop`) so a
  single roll runs with the lock set active.
- Reference count: **1** site. Idempotent.

#### 42b. `equipment_single_mod_stone` — One Modification Stone

- The embedded server helper `equipment_option_change_material_count_json`
  (`0x8A4DC8`) returns 1/2/4 stones for 0-1/2/3 locked lines. The site
  `0x8A4F3C` (`csinc x0, x8, xzr, gt`) becomes `mov x0, #1`.
- The client repeats the formula in `EquipmentOptionChangeGUI.UpdateCostValue`
  and in the confirmation dialog. The post-covault hook at `0xAB3388`
  branches to the cave at `0xB337B4` (0x4C bytes), patches
  `0x1CF069C` (`mov w1, w23` -> `mov w1, wzr`), then executes the displaced
  `ldp x24, x23, [sp, #0x30]` and returns to `0xAB338C`.
- Reference count: **3** (server site, cave, install branch). Idempotent.

#### 42c. `equipment_percent_options` — Percent-only Equipment Options

- Client `randoptiontable.unity3d`: direct flat (type 1) and scaled flat
  (type 4) rows get all six `_weight1.._weight6` set to 0. Type 2 rows
  keep their weights. For example, type 4 option `43010` stores 0.0267
  and displays +267 Counter Damage. The UI list still shows zero-weight
  options.
- Server table `fwt_randoption_rows(int&)::rows` at `0x621E60`: 1856 rows of
  40 bytes (`id`, group, equip, six grade weights at `+0x0C`, sort at `+0x24`).
  Flat option groups are `1, 2, 3, 4, 5, 6, 21, 23, 25, 26, 39, 41, 43`.
  All six grade weights are zeroed in these groups.
- Zero-weight fallback at `0x9A2AAC`: the picker sums the grade weights of the
  candidate rows and, when the total is zero, used to return the pool's
  best-quality row. A pool made only of flat rows therefore kept producing a
  flat option even with every weight zeroed. The branch below the empty-list
  check (`b.eq 0x9A2F0C`, `00230054`) becomes unconditional (`b 0x9A2F0C`,
  `18010014`), so such a pool returns an empty option id and the caller
  advances to the next attribute.
- Reference count: **597** (596 server weights + the fallback branch).
  Idempotent. Each equipment type and grade 1-5 keeps at least one weighted
  percentage row.
- Existing installs cache the extracted datatable under
  `/sdcard/Android/data/com.nexon.fwar/files/Resources/datatable/`; a fresh
  install extracts the patched asset. When testing over an existing install,
  replace the extracted file (or clear the app data) so the device does not
  keep the stock table.

#### 42d. `equipment_upgrade_10_guarantee` — +10 Upgrade Always Succeeds

- The server roll is `deterministic_success_roll_with_additive_basis_points_json`
  (`0xA17284`), called by `EquipmentGradeupStateAccess::gradeup` (`0x8A06C0`)
  with the success entry from `0x6BC0C0` and the fail entry from `0x6BC118`,
  both indexed by the current enchant level. Setting the **+9 fail entry**
  at `0x6BC160` (8 bytes, `595082` -> `0`) makes the roll return success
  before hashing; +0..+8 and +10 -> +11 keep their stock probabilities.
- Client `equipsuccessprobability.unity3d` row with `_baseEquipEnchant == 9`
  also gets `_successProb1.._successProb6 = 100000`, so the client's
  displayed/expected table agrees with the forced result (the server table is
  authoritative).
- Reference count: **1** SO site (plus the resource row). Idempotent.
- Validated with ten direct `GRADEUP_EQUIPMENT` requests: all ten +9 items
  reached +10; three +10 -> +11 requests still failed as expected.
- The +21..+26 equipment path is a separate table and remains covered by
  `upgrade_no_fail_above_20`.

#### 43. `rune_quality_factor` — Rune Attribute Quality Factor

- `rolled_rune_options_json` (`0xA2E65C`) computes the same `1/10000`
  mastery probability (`den = total - max(acc, 0)` at `0xA2EB9C`,
  `q = min(10000, (num - 1) / den)` at `0xA2EBAC`) using `[sp, #0x10]` (`450` max
  at mastery 15).
- Replaces `0xA2EB90` (`ldr x9, [sp, #0x10]`) with `movz x9, #<min(10000, 450 * factor)>`
  when `rune_quality_factor > 0`.
- Also excludes fixed-value attributes by setting the weights of 420 rows with
  value type 1 to zero in `kFwtRuneOptionRows` (`0x6ED510`, 3,808 rows, 48 bytes
  per row, weight at `+0x20`). Type 2 and 4 rows retain their original weights.
  The table is verified using reference and patched SHA-256 profiles; factor 0
  applies neither the bias nor the filter.
- The client mirror `files/Resources/datatable/runeoption.unity3d` (3,808 rows,
  `_weight` at the same logical position) is filtered in the same pass: every
  `_valueType == 1` row gets `_weight = 0`, and at least one percentage row must
  keep a positive weight or the build fails closed. Device validation is
  pending.
- Reference count: **1** site when `factor > 0` (0 when `factor == 0`). Idempotent.

#### 43b. `rune_option_quality` — Rune Options Maximum Mastery Row

- `rolled_rune_options_json` (`0xA2E65C`) looks up Lord mastery skill `20501`,
  clamps to 15, and indexes the weight table at `0x719F10`.
- Replaces `0xA2E700` (`bl mastery_level_in_state`) with `mov x0, #0xf` (`15`)
  so all rune option rolls use the level-15 mastery row.
- The mastery bonus is only a bias (`mastery * 30` out of `10000`, 4.5% at level
  15), so the feature also rewrites `kFwtRuneOptionRows` (`0x6ED510`, 48
  bytes/row, 3808 rows): inside each pool — same attribute type, grade, slot,
  fourth-attribute flag and value type — only the rows at the pool's highest
  `_quality` keep weight, and they receive the pool's whole weight. The table
  digest moves from `195f…`/`34da…` to `66a6…` (pink) or `ae14…` (percentage-only
  + pink), both pinned in the inspector.
- Reference count: **1** instruction site plus the table rewrite. Idempotent.


#### 44. `rune_box_random_roll` — 4★ Rune Box Rolls Slot and Type

- `pick_battle_rune_code` (`0x982C1C`) hashes fixed strings through
  `stable_reward_roll_text` (`0x987454`), making shop 4★ rune boxes always roll
  the identical rune.
- Installs a 68-byte xorshift32 cave at `0xB3981C` (`itanium_demangle::DtorName::printLeft`)
  using two 4-byte counters on page `0xBE2000` (`0xBE2F68` and `0xBE2F6C`):
  - `0x982F04` (`-slot`) calls the cave to mix the call counter into the slot roll.
  - `0x983178` (`b 0x98318c`, type-table loop entry) branches into the cave's
    type seed block (`0xB3981C + 36`) before walking `kFwtRuneRewardTypeRows`,
    so shop boxes cycle across all three rune types.
- `0x982D2C` (`-grade`), `0x983024` (`-quality`), and the unreachable `0x98314C`
  (`-type`) keep their original calls, preserving the deterministic star/quality
  and 4th-attribute behavior.
- Reference count: **3** (cave + `-slot` site + type-loop site). Idempotent.

#### 44c. `rune_upgrade_discount` — +12..+15 Rune Upgrades Guaranteed and 90% Off

- Server table `kFwtRuneEnchantRows` (`0x75797C`, 76 bytes/row, 15 rows): rows
  12, 13 and 14 lose their six failure weights (`_failProb1..6`, offsets
  `+28..+48`) and have the six gold costs (`_goldCost1..6`, offsets `+52..+72`)
  divided by ten. Rows 0..11 stay byte-identical. Verified against
  `RUNE_UPGRADE_TABLE_STOCK_SHA256`; patched digest is
  `RUNE_UPGRADE_TABLE_PATCHED_SHA256`.
- `rune_decided_enchant_cost_json` (`0x914F2C`): `0x8B48FD48 / 0x9B097D00`
  (sum + divide by 100, rounding to a hundred) becomes
  `0x8B0A0940 / 0xD37FF800` (`lsr #3` then `sdiv #100`), so the guaranteed
  one-step +12 price is the rounded total divided by ten (950,600 → 95,060).
- Client price display lives in encrypted code, so it is patched at startup:
  `RuneGradeUpPopup.GetEnchantCoast` (RVA `0x1C5B258`) sums the 72
  `runedecidedenchant` rows, applies the active discount and rounds down to the
  constant loaded at RVA `0x1C5B484` (`mov w9, #0x64`). A 76-byte cave at
  `0xB2A360` (hooked at `0xAB338C`, the covault epilogue's
  `ldp x26, x25, [sp, #0x20]`) calls `patch_words` (`0xAB575C`) to rewrite that
  word to `mov w9, #0x0a` (`0x52800149`), so the screen shows a tenth of the
  rounded total and matches the server.
- Client rows: `runeenchant.unity3d` gets the same treatment as the server table
  (`_patch_rune_upgrade_rows`: failure weights → 0, gold ÷ 10).
  `runedecidedenchant.unity3d` stays stock; its price is fixed by the cave.
- Reference count: **4** (table, decided-cost site, cave, install site).
  Idempotent; the whole option validates every target before writing, so a
  foreign library is left untouched.

#### 44b. `rune_box_random_type` — 4★ Rune Box Type Table

- Rewrites rows 11..13 of `kFwtRuneRewardTypeRows` (`0x61E134`, stride 16 bytes)
  from single rejected group-9 `runeType=8` (`(9, 10000, 8, 0)`) and unused
  groups 10..11 into a fair 3-row group 9 (`weight=1000` each for `runeType` 0,
  1, and 2).
- Covers the reward-mail table path (`gacha_weight_no = 9`); for shop boxes,
  `rune_box_random_roll` also randomizes the slot and type-loop seed.
- Reference count: **3** rows. Idempotent.

#### 45. `limit_break_cost_tenth` — 90% Hero Limit Break Cost

- Divides both `item_count` (`+16`) and `gold_cost` (`+20`) by 10 across all
  **45** rows of `kFwtCreatureLimitBreakCosts` (`0x756CF0`, 24 bytes/row),
  matching SHA-256 verification against the stock table.
- Mutually exclusive with `limit_break_gold_half` and `limit_break_cost_half`.
- During APK repacking, `core.apk_tooling` divides `_cost` and `_rewardValue02` in
  client asset `files/Resources/datatable/limitbreakcost.unity3d` by 10 to match
  (just as `limit_break_gold_half` and `limit_break_cost_half` divide the same
  client asset by 2 on their respective columns).
- Reference count: **45** rows. Idempotent.

#### 45b. `limit_break_cost_fixed` — Flat Hero Limit Break Cost

- Writes `item_count` (`+16`) = **100** and `gold_cost` (`+20`) = **1,000,000**
  into every one of the **45** rows, so a limit break costs the same at level 70
  and at level 118 instead of 4,000,000 → 190,000,000 gold.
- Accepts the stock table or any earlier discount profile as input (gold half,
  cost half, 90% off) and overwrites it; a discount applied afterwards is a
  no-op. The resulting table is pinned by SHA-256
  `fd6ade41…` and every row's level ladder, material item code and category
  (`17` = Balance Jade) are verified before any write.
- Mutually exclusive with `limit_break_cost_tenth`; `--all` ships this profile.
- Client side: `core.apk_tooling` sets `_rewardValue02` = 100 and `_cost` =
  1,000,000 in `files/Resources/datatable/limitbreakcost.unity3d`, so the Awake
  screen and its affordability gate show the same price the server charges. The
  client table is pinned by profile hash `48095e9a…`.
- Reference count: **45** rows. Idempotent.

#### 56. `limit_break_step_10` — Limit Break +10 Levels (to Lv 120)

- Updates `level_after` (`+4`) across all **45** rows of `kFwtCreatureLimitBreakCosts`
  (`0x756CF0`) to `min(120, ((level_before // 10) + 1) * 10)`: `70..78 -> 80`,
  `80..88 -> 90`, `90..98 -> 100`, `100..108 -> 110`, `110..118 -> 120`.
- `CREATURE_TRANSCEND` reads `row.level_after` (`[x21, #4]`) directly into
  `CreatureTranscendStateAccess::transcend`, while keeping the single-row gold and
  material cost independent of the jump size so it composes cleanly with stock
  costs, `limit_break_cost_tenth`, or `limit_break_cost_fixed`.
- Client side: `core.apk_tooling` updates `_levelAfter` in
  `files/Resources/datatable/limitbreakcost.unity3d` to match; `LimitBreakCostManager`,
  `HeroInfoLimitBreakPopupGUI`, and `LimitBreakDataManager` read `_levelAfter` and
  Lv 71–120 stats dynamically.
- Orthogonal to both cost profiles; `--all` ships this option (`13.03`).
- Reference count: **45** rows. Idempotent.

#### 57. `merlin_auto_support` — Merlin Slot-1 Auto Support (Magic infusion)

- Post-Covault runtime client installer at `0xAB3300` (`stlrb w8, [x9]` -> `bl 0xB2B1B4`, between `0xAB32F4` and `0xAB3304`) inside the unused `AbstractManglingParser::parseName` tail (`0xB2B1B4..0xB2B530`, 892 B), plus a 48 B awake-cooldown trampoline cave at `0xB2B620..0xB2B650` in the same function's remaining free tail.
- Installs four 4-word absolute trampolines into `libil2cpp.so` via `PATCH_IL2CPP_HELPER` (`0xAB575C`, reading `IL2CPP_BASE_CACHE` at `0xBE3798`):
  - `AIStatePhaseFindSupport::IsUseSupportSkillState` (`0x20EDBCC`)
  - `AIStatePhaseFindSupportInPlace::IsUseSupportSkillState` (`0x20F1AF0`)
  - `AIStatePhaseFindSupport::CompareFindTargetStep+0x178` (`0x20EEF2C`)
  - `AIStatePhaseFindSupportInPlace::CompareFindTargetStep+0x178` (`0x20F3338`)
- Triggers exclusively when `skillData._skillId == 1053188` (*Magic infusion*), `Character._characterType == 0`, `Player._isAutoPlay != 0`, `Camp._campType == 0`, and `Camp._members[0] == caster` (Slot 1).
- Accepts living allies (`target != caster`, `_isDead == 0`) carrying an Awakening skill (`(byte[skillData + 0x4d] | 1) == 5`) whose **true remaining cooldown == 1** — the `0xB2B3CC` check tail-calls client RVA `0x1606428` (`IsAwakeningSkill(skill) ? Skill::GetCurrentCoolTime(skill) : -1`) through the `0xB2B620` trampoline, because `[Skill + 0x30]` is a turns-elapsed counter (`Skill::ResetRemainCoolTime` `0x1B718E0` stores `0`), not the remaining cooldown — breaking ties among reachable targets by lowest team slot index in `Camp._members` (superseded by **14.03**, which ranks them by Awakening-skill damage instead). All HP/MP healing skills, manual play, Slots 2+, mercenaries, and non-player units keep stock AI; if all qualifying allies are out of range, normal attack AI runs.
- Reference count: **4** (1 hook site + 3 caves). Idempotent.
- **14.02 — skills before cells (same option)**: the 14.01 installer ends by branching (`0xB2B244`: `ret` -> `b 0xB30538`) into a 1112-byte cave in the dead `parseEncoding` tail right after `dungeon_recom_info`, which installs a fifth 4-word absolute trampoline at the `MoveEnableToTile` call site of `CharactersAI::InitActing` (client `0x1A35F68`, expected words `F9400268 AA1303E0 F9419109 F9419501`, verified against the decrypted client image). The 16-byte replacement is composed **at runtime** — `movz`/`movk` write `ldr x16, #8` and `br x16` into a stack buffer, and `adr x9, installer_entry` + `add x9, x9, #0xA8` supplies the body address — because a static `.quad` keeps the link-time VA and branches into unmapped memory (on-device `SIGSEGV` at `pc = 0xB305E0`). The body runs before the tile move and: (a) guards on Slot 1 / player camp / Auto Mode / non-semi-auto (`appointedTile == 0`, `appointedSkillIdx == -1`); (b) locates *Magic infusion* (`1053188`) in the descending scan (`[ai+0x7c]`..`[ai+0x80]`, skipping `preUsedSkillIndex`); (c) runs the **stock pair** (`CharactersAI::IsEnableUsingSkill` + virtual `EnableUseSkillToTarget`, `useportal = 1`) for every index above it — for Merlin that is the Awakening attack `1053189` in slot 4, which therefore beats the cell move; (d) runs the stock **support branch only** for *Magic infusion* (`AIStatePhaseFindSupport` object + ctor + controller `SetState`/`Execute`/`IsExecuted`, deliberately without the `FindAttackPlayer` fallback). A success resumes the client at `0x1A35F7C` (tile move skipped); any failure replays the four displaced words and resumes at `0x1A35F78` (stock). Merlin's ordinary attacks in slots 0/1 keep losing to the cell, as in stock; manual play, Slots 2+, mercenaries, monsters and PvP defense never reach the body's calls. Static client data (`0x3CD46E5`, `0x39AD548`, `0x39D78A0`) is addressed as `IL2CPP_BASE_CACHE + RVA`, never with a PC-relative `adrp`, because the body lives in the server library.
- **14.03 — strongest Awakening wins the tie (same option)**: the two cross-ally calls inside the 14.01 `CompareFindTargetStep + 0x178` body (`0xB2B468` / `0xB2B474`, both `bl slot_index_in_camp` at `0xB2B2F0`) are repointed to `awaken_power` at `0xB3088C` (cave offset `0x354`, appended after the 14.02 body; the cave grows 852 -> 1112 B). Only the two `bl` words change — the existing `cmp w0, w13` / `b.lt accept` sequence keeps meaning "lower rank wins" because the helper returns `0x7FFF - power`, and `0x7FFF` is exactly the "not found" value the old helper returned. Power is the summed damage multiplier of the ally's Awakening skill: the helper scans `Character._skills` (`[+0x40]` container, `[+0x18]` array, `[+0x18]` count, `[+0x20 + 8*i]` entries) for the skill whose `SkillData._useParameterKind` (`+0x4D`) satisfies `(v | 1) == 5`, then walks `SkillData._effect01..04` (`+0x3C`, `+0x40`, `+0x44`, `+0x48`), resolves each id through `SkillEffectTableManager::GetData` (client `0x202730C`) and adds `_effectValue` (`+0x38`, float, `4.25` = 425%) of every row whose `_skillEffectType` (`+0x20`) is `0` (damage). Values are scaled by 100 and truncated (`fmul` + `fcvtzs`) so the sum stays integral; non-damage effects (stun, heal, buff), unknown ids and allies without an Awakening skill contribute nothing, so a support Awakening always loses to a damaging one. Because the comparison ignores tile distance, two reachable allies are now chosen by hitting power regardless of how many steps each needs; equal power falls through to the stock distance rule (and to slot order for the same ally across tiles). PvE and PvP use the same rule — the 14.01 guard already restricts it to the player's Slot-1 Merlin in Auto Mode.

#### 58. `trait_multi_unique` — Traits: Unique Attributes per Multi-Roll Batch

- Hooks the 10-roll batch loop in `REQ_CHANGE_CREATURE_POTENTIAL` (`0x7FF69C`, `0x7FF7F4`) and `choose_potential_code_json` (`0x8BFE30`, `0x8C01E8`, `0x8C0524`, `0x8C07C8`) into a 240 B code cave at `0xB2B530..0xB2B620` inside the unused `AbstractManglingParser::parseName` tail.
- Tracks a 63-bit bitmask of already-rolled `potentialType`s in callee-saved `x27`, passing `(x27 << 1) | 1` into `x4` and storing full 64-bit `x4` at `[sp, #0x40]` so bit `0` keeps the stock `w4 = 1` current-slot `pt_code` exclusion while upper bits filter both Pass 1 (`0x8C01E8`) and Pass 2 (`0x8C0524`).
- Leaves single-roll callers (`w4 = 0` or `1`, upper bits zero) and `trait_allow_duplicates` (`13.02`) untouched. If a modded table exhausts unique candidates in Pass 2 (`0x8C07C8`), clears `[sp, #0x40]`'s batch mask while preserving bit `0` and replays Pass 2 once unconstrained.
- Reference count: **7** (1 cave + 6 hook sites). Idempotent.

#### 59. `trait_immunity_weight_x2` — Traits: Double Immunity Weights (Slots 3-5)

- Increases immunity Trait roll weights in `kFwtPotentialDataRows` (`0x6CBBC8`, 393 rows × 68 B) for Slots 3, 4, and 5: row `300` (`id = 35001`, `potentialType = 35`, col `6`), row `301` (`id = 36001`, `potentialType = 36`, col `12`), and row `302` (`id = 37001`, `potentialType = 37`, col `9`) from stock `335` to `20000` (2× normal stat weight `10000`).
- Each immunity pool has a single grade-5 row, so this patch commutes cleanly with `trait_max_quality` (`13.01`).
- Reference count: **3** rows. Idempotent.

#### 46. `soulgear_enchant_always` — Soulgear Enchant Always Succeeds

- `SoulgearGrowthStateAccess::apply` evaluates an FNV-1a roll against the
  upgrade chance tables (`0x6BC0C0` / `0x6BC118`) and writes the boolean
  verdict via `cset w8, lo` at `0x8B3B4C`.
- Forces the instruction to `mov w8, #1` so every gold-paid soulgear enchant
  succeeds (soulgear upgrades do not have a failure roll).
- Reference count: **1** site. Idempotent.

#### 47. `no_win_box` — Hide Phantom Cocoo Boxes

- The battle result uses `battle_has_mapped_coocoo_box` at `0x8DA77C` to advertise
  box slots even when the battle payload leaves them empty. Return false at that site.
- Subjugation populates the box list separately from regular drops. For example,
  the original post-battle reward group 140 produced 39 box entries in a ten-run
  sweep of hero-gene stage `116040`. The gate at `0x8CFC7C` checks the mapped
  hero gene ID after the normal reward path. Gene stages take the stock no-box
  exit. Other stages retain both stock box mapping checks.
- Reference count: **2** sites. Idempotent.

#### 51. `hero_exp_cap` — Hero EXP Cap & Un-transcended Limit Break Floor

- Battle and expedition EXP additions (`0x80963C` dungeon clear/sweep, `0x81831C`
  Tower of Dawn, `0x945E30` Expedition) previously summed reward EXP without
  calling `creature_max_total_exp_for_level_json` (`0xA245DC`), letting
  un-transcended 6★ heroes overflow into Lv71+ EXP. When `"level_max"` was
  `< 70`, `creature_level_max_value_json` (`0x901F00`) took the fallback at
  `0x902008` returning `min(max(level_from_exp, crs_level, 70), 120)` (`71`),
  which missed every even row (`70, 72..118`) in `LimitBreakCost` (`0x756CF0`).
- Forces `70` at `0x902008` (`mov w20, #0x46 ; b 0x9020b8`) so already-overflowed
  un-transcended heroes can immediately Limit Break (`70 -> 72`), and hooks
  `0x80963C`, `0x81831C`, and `0x945E30` into cave `0xB2AD70` (`168` B) to clamp
  all three EXP grants to `level_max` (`0xA245DC`) while preserving `w8` on the
  expedition path.
- Reference count: **4** sites (`1` floor + `3` hook branches) plus cave `0xB2AD70`. Always on; idempotent.

#### 52. `guild_raid_protection_persist` — Absolute Protection Persists for All Hits

- Every incoming hit on a protected ally runs `GameRule$$GetTargetReduceDamageRate`
  → `GuildSkillManager$$UseDamageReduceEffect` (0.682 client RVA `0x1877BA8`),
  whose consumption call `GuildSkillEffect$$RemoveMultiTarget` (`0x1BAAEBC`,
  call site RVA `0x1877C60`) permanently removes the ally from the shield's
  target list before returning the stored rate for that single hit.
- Additionally, `GuildSkillEffect$$OnEndTurnCamp` natively skipped effects
  `1048577..1048582` (`0x1BAA2FC: b.lo #0x1baa334`) and restricted expiry to
  `1048583` (`0x1BAA318: b.ne #0x1baa334`). Without clearing those two guards,
  Absolute Protection (`1048579`) never expired at the end of the turn.
- The runtime installer patches a 3-entry client table:
  1. `0x1877C60`: `bl GuildSkillEffect::RemoveMultiTarget` (`0x940CCC97`) →
     `bl GuildSkillEffect::GetMultiTarget` (`0x940CCC56`) so all hits are reduced.
  2. `0x1BAA2FC`: `b.lo #0x1baa334` (`0x540001C3`) → `nop` (`0xD503201F`) to
     include `1048579` in `OnEndTurnCamp` turn-end expiry.
  3. `0x1BAA318`: `b.ne #0x1baa334` (`0x540000E1`) → `nop` (`0xD503201F`) so
     `1048579` expires cleanly at the end of the 1-turn window.
- Delivery: mid-function hook at `0xAB32F4` (`mov w8, #1`, original
  `0x52800028` inside the common exit path of `patch_offline_convenience_flow`
  after the `libil2cpp.so` base cache write at `0xAB0064`) calls the
  424-byte self-healing installer cave at `0xB2AE18..0xB2AFC0` (free tail of
  `AbstractManglingParser::parseType`). For each entry, the cave validates and
  calls `PATCH_IL2CPP_HELPER` (`0xAB575C`), and if the helper declines while the
  stock word is present, applies the write directly via `sysconf(_SC_PAGESIZE)`
  (`0xB476C0`), `mprotect` RWX (`0xB476D0`), `0xB41794` icache flush, and
  `mprotect` RX back before replaying `mov w8, #1` and returning to `0xAB32F8`.
- Verified in Guild Raid on device (2.5.55): protects integrally for 1 turn across
  all incoming hits and expires cleanly on turn end. Enabled in `--all`.
- Reference count: **2** (hook site + cave). Idempotent; composes with
  07.06/07.07/07.08 (standalone: the stock level-scaled magnitude persists
  for all hits for 1 turn).

#### 60. `dungeon_recom_info` — Mercenary Auto-Select Recommendations (`DUNGEON_RECOM_INFO`)

- The stock embedded server is one of the protocol's empty stubs: it never
  implements `DUNGEON_RECOM_INFO`, answering the generic
  `{"CMD":..,"packet_no":..,"ERROR":0,"msg":""}` ack. The client's
  `Result_DUNGEON_RECOM_INFO` parses `recom_list` to rank candidate friend
  mercenaries for the pre-battle "auto select" — with the stock ack there is
  never a candidate, so no mercenary is picked automatically even though
  manual selection (via `GET_FRIEND_LIST`, 164 KB of friends) works.
- The cave wraps the only dispatch call in
  `fwt::EmbeddedStub::handle_json_request` (`0x7DAED0`, `bl 0x7E4030`,
  original word `0x94002458`). At that site `x8` is the response sret
  buffer, `x0` the config whose first member is the state-path
  `std::string`, and `x1` the request `std::string` (libc++ SSO layout:
  byte0 bit0 set -> long, size at +8, data at +0x10; else size = byte0>>1,
  characters inline at +1).
- Fast path: the cave byte-scans the request payload for
  `"DUNGEON_RECOM_INFO"` (two qword compares + one halfword per position,
  `x8/x0/x1` and the link register untouched) and forwards every other CMD
  to the stock dispatcher — one short scan of overhead per request.
- Matched path: echoes `packet_no` through the server's own `int_field`
  (`0x7E08B8`, default 900), loads the state via `load_state_snapshot`
  (`0x7DDECC`; `+0x00` valid byte, `+0x08` state JSON string), builds
  `recom_list` with `friend_list_json` (`0x8D5674`, key `"friends"` — the
  same source `GET_FRIEND_LIST` serves as `friend_lists` and `START_GAME`
  as `recommend_list`), and assembles the response with
  `basic_string(char const*)` (`0x7DBFB0`), `operator+` (`0x7E1750`) and
  `~basic_string` (`0xAD913C`); the final concatenation lands directly in
  the caller's sret.
- Fallback: when the snapshot's valid byte is 0 the cave answers the plain
  ack (no `recom_list`), exactly the stock behavior, without destroying the
  (never constructed) snapshot.
- Cave host: `0xB301F8` in the unused
  `itanium_demangle::AbstractManglingParser::parseEncoding` body (3620 B,
  demangler-only profile — the same dead-code family as the shipped
  campaign caves); 832 bytes, rebuilt by
  `tools/gen_dungeon_recom_cave.py`, embedded in
  `core/dungeon_recom_info.py`.
- Emulated end-to-end with Unicorn (both string layouts, passthrough
  register/ABI preservation, matched response bytes, plain-ack fallback,
  edge-length payloads, single-digit packet_no echo) in
  `tests/test_dungeon_recom_info.py`; validated against the reference APK
  stock bytes and `patch_inspector`.
- Reference count: **2** (hook site + cave). Always-on bug fix (08.08), no
  CLI flag and no GUI control; idempotent.

---

## 4. Reverse-Engineering Findings (Modifiable Code Map)

### 4.1 Local Server Symbols

`libfwt_local_server.so` retains C++ symbols (`nm -C`). Key functions:

| Symbol | Address | Role |
|---|---:|---|
| `refresh_laboratory_charge_state` | `0xA634F0` | Updates lab charges; uses `0x1c20` (7200s) in loop |
| `laboratory_use_fields` | `0xA64D88` | Applies laboratory tool usage |
| `default_laboratory_info_json` | `0xA63DA8` | Default laboratory JSON |
| `normalize_laboratory_info_rows` | `0xA64040` | Normalizes laboratory rows |
| `laboratory_tool_info_for_type` | `0xA66840` | Builds `left_time`/`use_count` per tool type |
| `LaboratoryStateAccess::refresh` | `0x918690` | Refreshes laboratory state |
| `LaboratoryStateAccess::use` | `0x918F54` | Uses a laboratory tool |
| `BattleSecondStartStateAccess::charge` | `0x8D7324` | Deducts stamina on second battle start |
| `BattleStartStateAccess::issue` | `0x8D539C` | Issues initial battle start |
| `StaminaItemStateAccess::use_potion` | `0x8EBE80` | Uses stamina potion |
| `spend_item_count` | `0x8CE418` | Consumes item from inventory |
| `mark_stamina_timer_started` | `0x8CE9D4` | Marks stamina timer start |
| `refresh_stamina_state` | `0x888618` | Refreshes stamina in state |
| `stamina_left_seconds_for_state` | `0x9199B4` | Computes remaining seconds for stamina tick |
| `ShopStaminaRechargeStateAccess::recharge_normal` | `0x888364` | Shop normal stamina recharge |
| `ShopStaminaRechargeStateAccess::recharge_pvp` | `0x888C00` | Shop PVP stamina recharge |
| `kFwtCreatureLimitBreakCosts` | `0x756CF0` | Creature limit-break cost table |
| `kFwtRandomRewardRows` | `0x719F10` | 618-row reward table (alchemy capsules = tables 102–111) |
| `EquipmentDisassembleStateAccess::disassemble` | `0x89C1C8` | Equipment recycling/alchemy handler |
| `equipment_infinite_transcend_success_percent` | `0x6BAE64` | +21..+26 success table (100/90/80/70/60/50) |
| `patch_offline_convenience_flow` | `0xAAFDF8` | Installs runtime client hooks via `patch_words` |

### 4.2 Laboratory Tables

- `LaboratoryCooltime` (Gold Cylinder, `tool_type 1`): 30 rows,
  `work_idx:1`, `"cooltime":21600`, `"cash_count":3`.
- `LaboratoryCount` (Mana Stone Compactor, `tool_type 2`): 30 rows,
  `work_idx:1`, `"cooltime":7200`, `"use_count":5`, `"cash_count":5`;
  level 7 has `"reward":200`, matching the Mana Stone panel.
- `LaboratoryTime`/`LaboratoryTimeZone` (Energy Flask, `tool_type 3`):
  `reward=100`, windows 12:00–15:00 and 18:00–21:00 (3h each); not the
  5-charge cooldown.
- `LaboratoryType`: `tool_type` 1 = Gold Cylinder, 2 = Mana Stone Compactor,
  3 = Energy Flask, 4 = Genetic Analyzer.
- Inside `.so` there are **two copies** of the `LaboratoryCount` table, totaling
  **60 occurrences** of `"cooltime":7200`.
- The JSON is used for default server state initialization, whereas
  `refresh_laboratory_charge_state` uses hardcoded `0x1c20` in its loop and the
  client UI reads the external datatable.
- **Conclusion:** the code patch plus the external `LaboratoryCount` datatable
  update the Mana Stone Compactor (`tool_type 2`) timer; the UI confirmed
  `Remaining Time 02:59:57` and the save recorded `left_time=10800`. The daily
  Energy Flask (`tool_type 3`) already has 3h windows and is unaffected.

### 4.3 IL2CPP Client — Methods & RVAs

| Type::Method | RVA | Purpose |
|---|---:|---|
| `EquipmentMenuGUI::BlockSelect` | `0x1CE9214` (hook `0x1CE93F8`) | Select All 4★/5★ |
| `Locale::GetText` | `0x12BB4D4`, `0x146D430` | Localization |
| `Localization` (get/set/language) | `0x15BF3F0…` | Localization |
| `LanguageSelection::Start` | `0x2408690` | Language selection |
| `GameRule::hasEnoughEnergyStamina` | `0x15F7810` | Stamina validation |
| `GameRule::GetTimeForFullStamina` | `0x1603620` | Stamina timer |
| `DungeonData::get_costStamina` | `0x16A434C` | Displayed/validated stage stamina cost |
| `LimitBreakCostManager` | `0x19CAE2C…` | Limit-break costs |
| `HeroInfoLimitBreakPopupGUI::GetNeededGoldCostLimitBreak` | `0x1C2B054` | Limit-break cost UI |
| `LaboratoryCount::get_cooltime` | `0x1E96944` | Mana Stone Compactor timer in client |
| `LaboratoryCooltime::get_cooltime` | `0x1E95B5C` | Gold Cylinder timer in client |
| `LaboratoryType`/`Laboratory_tool_info` | `0x2407C0C…` / `0x2408688` | Laboratory data |
| `EventCoinShopGUI` | `0x1936CFC…` | Event shop |
| `GuildRaidRewardManager` | `0x1B9B3C8…` | Guild raid |
| `TranscendTableManager`/`GemAttributes` | `0x1A5E654…`/`0x17F4704…` | Transcendence / gems |

### 4.4 AppSealing & Static Disassembly Limits

- `libil2cpp.so` at rest has `.text` ~73% zero-filled and encrypted segments;
  methods such as `BlockSelect` are **zeroed** on disk and other regions contain
  high-entropy ciphertext that Capstone cannot decode as ARM64.
- Metadata is readable in plaintext and method RVAs are valid, but **method
  bodies** only exist in memory after runtime decryption.
- To inspect client method bodies: dump `libil2cpp.so` from memory using Frida on
  MuMu and run Capstone/Ghidra against the memory dump.
- `libfwt_local_server.so` is **not** AppSealing-protected and is the primary
  target for static binary patches.

### 4.5 Relevant Strings & Items

- `stamina_item` → `47500601` in `.so` (stamina item ID).
- `GameDefs::StaminaCountItemID`, `GameDefs::StaminaRechargeID`,
  `GameDefs::MaxStamina` in client metadata.
- `StaminaItemStateAccess::use_potion` normal branch: `stamina = stamina + max_stamina`.
- `mark_stamina_timer_started` and `stamina_update_epoch` govern the recharge timer.
- `Result_START_GAME_2ND.left_stamina` is the response field from second battle start.

---

## 5. Resolved & Known Investigations

### 5.1 `flask_3h` — 3h Mana Stone Compactor Timer

**Evidence:**

- Decompiled `refresh_laboratory_charge_state` uses `0x1c20` (7200) in its charge
  loop (`uVar47 = 0x1c20`), and the code patch updates two `mov` instructions to
  `0x2a30` (10800).
- The `LaboratoryCount` table in `.so` and on the client still had
  `"cooltime":7200` (60 occurrences in `.so`).
- The client has `LaboratoryCount::get_cooltime` at `0x1E96944` and the lab UI
  reads the local datatable to render timer progress.
- `laboratorytype.unity3d` identifies `tool_type 2` as the Mana Stone Compactor;
  `LaboratoryCount` has `_useCount=5`, `_reward` 80–660, and at level 7
  `_reward=200` — matching the Mana Stone Compactor UI panel.
- `laboratorytimezone.unity3d` defines the daily Energy Flask windows
  (12:00–15:00 and 18:00–21:00, 3h each) with no 7200s `_cooltime`.

**Confirmed root cause:** the server accumulated Mana Stone charges every 2h
(`0x1c20`), while client UI/validation read the external `LaboratoryCount`
datatable (`_cooltime=7200`). The historical `flask_3h` name is retained, targeting
`tool_type 2`.

**Applied solution (2026-11-07):**

1. Kept the server code patch at `0xA63904/0xA6390C/0xA6649C`.
2. Decrypted the external datatable `laboratorycount.unity3d`, updated all 30
   `_cooltime` rows to `10800`, re-encrypted it with the `.env` key/IV, and
   pushed it to `.120`. Original backed up at
   `backups/datatables-2026-11-07/laboratorycount.original.unity3d`.
3. Reproducible CLI tool: `tools/patch_labcount_datatable.py` (UnityPy via
   `uv --with`; optional `--push`).
4. **Runtime validated:** consuming a Mana Stone Compactor charge on `.120`
   produced `left_time=10800` in the save and `Remaining Time 02:59:57` in the UI.
   The Gold Cylinder displayed `Maximum Production Time 06:00:00`.

### 5.2 `stamina_cost_half` — Final Decision (Half-Debit)

**Evidence:**

- The patch at `0x8D744C` halves the server-side subtraction.
- The client has `DungeonData::get_costStamina` at `0x16A434C` and uses
  `DungeonData._costStamina` to display the cost and gate stage entry.
- `Result_START_GAME_2ND.left_stamina` is returned to the client, which updates
  current stamina after entry, though pre-entry client validation still checks the
  full cost.

**Final decision (2026-11-07):** use **server-side half debit** in `--all`:

- the APK is built with `stamina_cost_half=True` (patch `0x8D744C`) and **without**
  `stamina_cashback`;
- the client still requires full stamina to enter and displays the full cost
  (accepted limitation without modifying client datatables);
- `--stamina-cashback` remains explicit and experimental, is **not included in
  `--all`**, and is currently blocked by the read-only server endpoint;
- the two flags are mutually exclusive to prevent double reduction.

**Live cashback test result (2026-11-07):** battle `6820155` (cost 4) completed.
The companion detected the debit (`stamina 543 -> 539`) and sent a refund of 2,
but the embedded server ignored the requested stamina: `GET_MY_INFO` and the save
file stayed at 539 because `fwt::handle_update_stamina_time` is read-only.

### 5.3 `stamina_potion_1000` — Runtime Validated

- Applied at `0x8EC1E8` (`csinc` → `mov x21, #1000`).
- Byte and inspector tests pass.
- **Validated in-game (2026-11-07):** normal stamina potion granted 1,000 stamina
  on MuMu `.120`.
- Save state confirms overcap is supported (`stamina=443`, `max_stamina=57`).

---

## 6. Workflow for Authoring New Patches

1. **Identify target behavior** in client/server:
   - IL2CPP metadata + REA for method names/RVAs;
   - `fwt::` symbols and `.so` strings for the embedded server.
2. **Inspect code**:
   - server `.so`: direct Capstone/Ghidra disassembly;
   - client: Frida memory dump of decrypted `libil2cpp.so`.
3. **Validate patch site**:
   - original bytes, instruction semantics, function boundaries, and offsets;
   - SHA-256 of tables/cave slots;
   - ensure idempotency.
4. **Implement**:
   - constants + `apply_*` routine in [`core/core_patches.py`](../core/core_patches.py);
   - flag in `PatchOptions`;
   - CLI flag in [`fwt_patcher.py`](../fwt_patcher.py) and checkbox in [`gui/main_window.py`](../gui/main_window.py);
   - detection in [`core/patch_inspector.py`](../core/patch_inspector.py);
   - unit and integration tests under `tests/`.
5. **Build & verify**:
   - `pytest`, `ruff`, `mypy`, `compileall`;
   - build APK and run `--inspect`;
   - install on MuMu and test with a save backup.
6. **Document** in this specification and in `README.md`.

### 6.1 Adding a Runtime Client Hook

The local server uses `patch_words` to write bytes into the decrypted client at
startup. Following the `select_all_4_5` pattern:

1. Pick a `bl` site in `patch_offline_convenience_flow` (e.g., `0xAB0118`);
2. Create a cave slot in `.so` (e.g., `0xB33634`) that invokes `patch_words(RVA, bytes, len)`;
3. Redirect the installer `bl` to the cave;
4. Validate both the cave slot and installer site via SHA-256 / original bytes;
5. Register the cave range in `validate_cave_layout()`;
6. Test at runtime on MuMu.

Candidate client RVAs for future hooks:
- `LaboratoryCount::get_cooltime` = `0x1E96944`;
- `DungeonData::get_costStamina` = `0x16A434C`.

---

## 7. Security & Tooling Maintenance

- Python dependencies pinned in `requirements.txt` / `requirements-dev.txt`;
  `pip-audit` reports zero known vulnerabilities.
- CI runs on `ubuntu-24.04` and `windows-latest` across Python 3.12 and 3.13
  executing `ruff`, `compileall`, and `pytest`.
- Repository contribution governance is enforced via `.github/CODEOWNERS` and
  authorial workflows (`pr-policy.yml`, `pr-policy-comment.yml`,
  `issue-triage.yml`), verified by `tests/test_github_workflows.py`.
- `.env` and `.venv` are git-ignored; keep `.env` permissions restricted (`chmod 600` on Linux).
- Never print or commit handshake or datatable cipher keys.

---

## 8. Cross-Platform Build Reproducibility

- Reference build 2.5.1 (2026-11-08, Windows): 33 active features, `--all` with
  server-side half debit (`stamina_half=True`, `stamina_cashback=False`),
  1,423 daily event-limit rows, Kraken Scale event reward, Coocoo Level x2,
  Unknown Paradise battleship 50% / crystal 90% discounts, corrected Ruby
  Hammer recycling rewards, extended Nephthys item trampoline, internal
  `laboratorytimezone`/`honorreward`/`equipreward`/`limitbreakcost`/
  `crystalskillcost` assets plus Sacred Lands set/ticket assets patched,
  16 KB aligned and signed:
  - Windows APK: `output/FWT-Reborn-Patched-2.5.1.apk`
  - Windows APK SHA-256: `f99597e745c62573d791126ad5d29bb20efda8d0837c5fc29dd884e0ecea80f3`
  - SO SHA-256: `590af12ed05c48a164fa0a63014941850c9f802717774129531820b1f16bbff2`
  - DEX SHA-256: `1aa6522e96705c11e796e0f51c242e95150390b56648739d8aca38361da95ba8`
  - Resource archive SHA-256:
    `1F560FF82F4911230FAA5645F0F4833209C763820182A8E585310FB78B73D570`
- The **payloads** (SO, DEX and internal resource archive) are byte-identical
  between Windows and Linux. The full APK container hashes differ because the
  host zlib recompresses the unrelated outer APK entries differently.
- Runtime tests on 2026-11-08
  validated Honor Coins 60, Devil's Soul EXP 31,900, Multi Extraction removing
  four 5★ quality-4/5 items, Unknown Paradise `WORLDBOSS_RESULT_EVENT` granting
  290 Kraken Scales (`280001`), event-shop type-3/type-4 counts at zero,
  device Sacred Lands grade `[4, 4]` with ticket rows for `10001`/`10004`, and
  the Coocoo Garden table at `0x735488` reporting 20/20 doubled rows. The 2.5.0
  runtime pass additionally confirmed four level-440 coocoos from Rock Garden
  10, four level-440 coocoos per Subjugation sweep (12 for 3 sweeps), the
  battleship part 1→2 cost at 2,500 gold, and the crystal skill 1→2 cost at 5
  Kraken Scales (590 → 585). The 2.5.1 alchemy tables were verified in both
  the SO and client `equipreward.unity3d`: 102/103 = Ruby Hammer `16921863`,
  104/105 = Black Dragon's Hammer IV `16930082`, 107–111 = Past Breaking
  Hammer `16930193`.
- APK-only generations no longer create a ZIP wrapper; the output filename
  always includes the patcher version (`FWT-Reborn-Patched-<version>.apk`).
  The patcher suite ZIP follows the same rule
  (`FWT-Reborn-Patcher-Suite-<version>.zip`), including when a custom output
  name is supplied.
- Useful commands:

```bash
.venv/bin/python -m pytest -q
.venv/bin/python fwt_patcher.py --all --output output/FWT-Reborn-Patched-2.5.1-linux.apk
```

---

## 9. Feature Backlog

- [x] Stamina Potion 1000 (`stamina_potion_1000`) — validated at runtime.
- [x] `flask_3h`: server code patch + external datatable `_cooltime=10800`;
      validated on Mana Stone Compactor (UI `02:59:57`, `left_time=10800`).
      Daily Energy Flask already has 3h windows and is unaffected.
- [x] `event_limits_daily`: event-limited shop rows reset daily (Dragon Fang
      dialog `0/3` daily validated on device).
- [x] `event_gene_unlimited`: gene rows use the 255 no-limit sentinel (gene
      purchase dialog has no limit line).
- [x] Pit of Nephthys/Lost Island item multiplier: 10x subjugation returned 400
      items, 10,000 gold and 580 event coins on 2026-11-08.
- [x] `select_all_4_5`: runtime validated; multi-extraction removed four 5★ quality-4/5 items (gauge-limited).
- [x] `sacred_lands_restore`: grade 4 in all localized set tables, group `4028`
      added to ★4 ticket lists `10001`/`10004`, bootstrap critical hash updated.
- [x] Kraken Scale: World Boss event `10002` reward row now grants item
      `2621441`; live `WORLDBOSS_RESULT_EVENT` returned 290 scales.
- [x] Dungeon Subjugation Ticket sweep: client **Subjugate** on Rock Coocoo's
      Garden 10 (3 sweeps) returned 12 level-440 coocoos (4 per sweep), 16,500
      gold and 480 event coins; `clear_cnt` went 1 → 4. The 10x item multiplier
      does not scale exp creatures, so `coocoo_level_x2` supplies the level-440
      compensation.
- [x] `coocoo_level_x2`: Rock Coocoo's Garden 10 drops four level-440 coocoos;
      save contains four new `00210841` level-440 monsters.
- [x] `ship_parts_90_off` (originally 2.5.4 `ship_parts_half`): part 1 level 1→2 charged 2,500 gold in 2.5.4, raised to 90% off (500 gold, original 5,000) in 2.5.5.
- [x] `crystal_skill_90_off`: skill 1 level 1→2 charged 5 Kraken Scales
      (590 → 585).
- [x] `guild_raid_mercenary`: weekday-aware self-projection cave moved to `0xB34860` (`itanium_demangle::AbstractManglingParser::parseUnnamedTypeName`), plus post-covault client filter cave at `0xAB3380` -> `0xB336D8` (RVA `0x1EE5220`).
- [x] Multi Extraction item-cave `x21` flag replaced by a stack flag.
- [x] `stamina_cashback` *(removed in 2.5.35; superseded by `stamina_cost_half`)*: the
      host companion approach was **blocked** by read-only `UPDATE_STAMINA_TIME`
      in the embedded server (confirmed in live test `6820155`), so `--all` uses
      server-side `stamina_cost_half` instead.
- [ ] Increase max stamina (potion overcap already confirmed: 443/57).
- [ ] Explore additional client-side localization (`Locale::GetText`, `Localization`).
- [ ] Explore Event Shop / Guild Raid / Transcendence via IL2CPP metadata.
- [ ] Frida memory dump of decrypted `libil2cpp.so` and Ghidra analysis of client methods.
- [ ] Property-based tests with `hypothesis` for patch idempotency.

---

## 10. Internal References

- [`core/core_patches.py`](../core/core_patches.py) — binary patch engine and constants.
- [`core/patch_inspector.py`](../core/patch_inspector.py) — feature detection and APK verification.
- [`docs/SERVER_ARCHITECTURE_AND_REVERSE_ENGINEERING.md`](SERVER_ARCHITECTURE_AND_REVERSE_ENGINEERING.md) — detailed server architecture and reverse-engineering guide.
- [`scripts/setup-linux-toolchain.sh`](../scripts/setup-linux-toolchain.sh) — rootless JDK + Android SDK installer.
- [`README.md`](../README.md) — setup, `.venv`, `.env`, CLI/GUI usage, and troubleshooting.
- [`tools/extract_env_keys.py`](../tools/extract_env_keys.py) — extracts `.env` cipher credentials from the user's reference APK.
- [`tools/patch_labcount_datatable.py`](../tools/patch_labcount_datatable.py) — external `laboratorycount.unity3d` (`_cooltime=10800`) patcher using UnityPy/cryptography.

## 11. Feature 02.08 — Complete Costume Packages

`--costume-packages-all` changes Lucky Costume Special Boxes 3 and 4 (offers
`75151` and `75187`) to emit one normal shop mail for each distinct owned
costume passing the original eligibility rules. Each offer has its own daily
limit of ten purchases; original currencies and prices remain unchanged. The player can
collect all matching package mails together using the shop mailbox's Claim All.
A purchase with no eligible costumes was rejected without a charge on the
disposable emulator.

The reward loop is scoped to component codes `75150` and `75186`; it changes
selection, not the existing eligibility filters. Native server sites `0x9846A8`
and `0x9846B8` branch to caves `0xB2A3AC` and `0xB2A4AC`. The runtime client
installer at `0xAB3390` uses cave `0xB2A5AC` to replace verified decrypted
IL2CPP RVA `0x1625844` (16 bytes). The handler calls the displaced original
function and only changes its result for matching component mails. Full cave
hashes, original hook words, and both copies of each offer record are verified
before mutation; mixed states are rejected. The inspector checks all static
sites, not whether a runtime client patch succeeded on an unknown build.

On a disposable emulator the ruby offer produced 100 unique eligible costume
mails and Claim All raised each matching count by exactly one. The tenth daily ruby purchase succeeded and the eleventh was rejected; the
existing daily reset was separately observed, and an empty owned list failed
without charge. Both component branches are covered by instruction emulation. On the
disposable emulator, the patched HIVE flow delivered 100 distinct costume mails;
the tenth package-3 purchase succeeded and the next was blocked by the shop. Cave trap testing covered lobby, shop,
gems, arena and a campaign battle, and does not establish every possible path.

A direct `SHOP_BUY` request for cash-priced offer `75151` to the disposable
local server returned `cash-priced products are disabled in local preservation
mode`; no package-3 purchase or reward occurred. The user subsequently purchased the offer through `SHOP_BUY_CASH_HIVE`; the
primary emulator log reported success and its save recorded one purchase and
one original random costume mail. The patch preserves the price and payment
handling.

#### 61. `guild_raid_skill_turn_gate` — Guild Raid Lord Skills Auto-Cast Once per Turn

- Stock auto-cast executes a reserved lord skill the moment `lordGauge >= 15`
  and re-executes it whenever the gauge recharges inside the same turn. For
  one-turn effects (Absolute Protection, Combat Support) and burst damage
  already delivered (Guild Shelling) the second same-turn cast wastes gauge.
- The boot flow's common exit path carries six one-word installer sites;
  `0xAB3374` (`mov w4, w19`) runs last, after
  `0xAB32F4` (07.09), `0xAB3300` (14.01), `0xAB3304` (12.03),
  `0xAB335C` (07.06) and `0xAB3370` (08.07). The cave replays the word and
  resumes at `0xAB3378`.
- Client site `0x018E6FF0` is the last stock hold gate of
  `Player$$ExecuteReservedLordSkill` (`0x018E6DAC`): after the
  `stageType == 7` branch (`0x018E6F48..0x018E6F50`), the skill id load
  (`mov w20, w0` at `0x018E6FD0`) and the gauge check
  (`cmp w0, #0xf` at `0x018E6E74`), every one of the four guild skills passes
  `mov w0,w20 / mov x1,xzr / bl 0x17edd98 / tbnz w0,#0 -> 0x018E7334` — and no
  branch lands inside the 16-byte window, which ends exactly where the 07.06
  stub (`0x018E7060..0x018E706F`) begins.
- State lives at `0xBE62C8..0xBE62D8` — the RW page tail immediately after
  `alex_awakening_scratch` (`0xBE6268..0xBE62C8`), beyond the last
  `PT_LOAD p_memsz` yet inside the loader-mapped last page, outside every
  symbol — the same technique 12.01 already ships. Instance change resets the
  whole slot; turn change clears only the mask.
- `d = w20 - 0x20000001`: `d == 1` (Fire Support) and `d > 3` (unexpected)
  resume unmarked — the 07.06 minion gate keeps sole authority over Fire
  Support; `d in {0, 2, 3}` gate on bits `0, 1, 2` respectively. A null
  `GameStage::get_instance` (`0x01640248`) fails open to stock; the turn
  comes from `GameStage::get_currentTurnNo` (`0x01641F38`, 0-based).
- Reference patch count: 2 (hook + cave). Emulated end-to-end with Unicorn in
  `tests/test_guild_raid_skill_turn_gate.py`, including the installer matrix
  (helper writes / refuses / no cached base) and the runtime matrix
  (first cast, same-turn hold per skill, turn-advance release, Fire Support
  unmarked, unknown ids, stock-hold precedence, null-instance fail-open,
  instance-change reset, frame discipline on both exits).
