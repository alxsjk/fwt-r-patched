# Changelog

All notable changes to **FWT Reborn Patch** are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [2.5.53] - 2026-11-20

### Added
- **Surprise Transcendence Package 2 (02.10)**: Offer 75103 costs 500 diamonds and delivers ten Ultimate Equipment Transcendence Tickets and ten Universal Transcendence Tickets. Other promotions keep the stock package.

### Fixed
- **Hero-gene Subjugation rewards (08.03)**: Disable the Coocoo Box bonus branch in stages that drop hero genes. Regular drops, gene rewards, and bonuses in stages without genes retain their existing rules.

### Known Issues
- **[KB-001](docs/KNOWN_BUGS.md) — Mythical Stone display resets after restart (02.07)**: purchases from the Special Product offer are charged, delivered, persisted by the server, and usable in the same session, but the inventory and costume enchant screens show zero after restarting the game. No stones are lost. Workaround: spend the stones in the session in which they are bought.

## [2.5.52] - 2026-11-20

### Fixed
- **Percent-only equipment options (03.05)**: Exclude scaled flat options such as +267 Counter Damage and +67 Defense. Combining this filter with 03.02 still gives maximum-quality rolls for the eligible percentage options.

## [2.5.51] - 2026-11-20

### Fixed
- **Equipment option potions**: The release enables both percentage-only rolls and maximum-quality ("always pink") rolls. Existing locked options retain their values.

### Changed
- **Alex Skill 3 (`--alex-rebalance`)**: Giga-break now uses the cast range of Jakyak's *Do not Chase me* and retains Alex's existing area of effect.

### Added
- **Unknown Paradise full ship repair (06.10)**: Restore the ship to full HP on the first eligible timed repair tick, Instant Repair, or revive.
- **Cipher key extractor ([tools/extract_env_keys.py](tools/extract_env_keys.py))**: one-command setup for the `.env` cipher variables. The secrets live inside the game's own asset pack: a 484-byte Unity `TextAsset` (`DefineResources/Assembly`, inside `assets/bin/Data/datapack.unity3d`) whose blob embeds its own single-DES key and IV, so no secret values ship with the repository. Validated against the reference APK (`fwt_0.682_offline_v1574.apk`, 966 MB): the blob is recovered with UnityPy, decrypts to 15 secret strings and maps to the 10 cipher variables (`FWT_CACHE_CRYPT_*`, `FWT_DATATABLE_CRYPT_*` including the `_REVERSED` forms, `FWT_NETWORK_CRYPT_*`, `FWT_ID_KEY_*`) following the documented `.env` conventions. Prints key lengths only, never the values. Adds unit tests (synthetic blob round-trip, `.env` merge) and an integration test gated on the reference APK; the README quick start documents the step.
- **GitHub Authorial Governance Workflows**: added `.github/workflows/pr-policy.yml`, `.github/workflows/pr-policy-comment.yml`, and `.github/workflows/issue-triage.yml`, updated issue/PR templates and `CONTRIBUTING.md` to enforce the issue-first `needs-triage` -> `approved` contribution workflow, and added fork-safety tests in `tests/test_github_workflows.py`.

### Docs
- Translated the awakening guide to English and renamed it to [docs/HERO_AWAKENING_GUIDE.md](docs/HERO_AWAKENING_GUIDE.md) (replacing the former non-English draft); removed dead internal-only references from the guide, the feature catalog and the patch specification.
- Updated [README.md](README.md) and `docs/*.md` to match the `2.5.50` codebase (including current `--all` counts, `04.05` rune upgrade status, shipped `12.01`/`12.02` hero modifications, CI OS matrix, code-cave allocations, and `[assets]` extra) and converted remaining non-English identifiers/output strings in `tools/patch_audit.py` and `tests/test_no_win_box.py` to English.

## [2.5.50] - 2026-11-18

### Fixed
- **Alex Awake (`--alex-rebalance`, `0x100185`)**: Fixed the Boss swap targeting/ordering regression and reduced the post-swap Thornbush terrain transformation to a 1-cell radius centered on the Boss's destination tile (`Hook 5b` / `0x10018501`).
- **Code Review Remediations**: Resolved static analysis, path-handling, APK validation, ELF segment bounds/translation, and resource-safety findings across `core/`, `gui/`, `tools/`, and `tests/`.

### Changed
- Translated remaining non-English helper scripts, comments, CLI messages, and test internals across `tools/` and `tests/` to English, and normalized documentation IP placeholders away from private LAN addresses.

## [2.5.49] - 2026-11-18

### Added
- **Alex Skill, Passive & Awake Rebalance (`--alex-rebalance`, feature `12.02`, included in `--all`)**:
  - **Skill 1 (`1048961`)**: Updated geometry to match Phantom's Skill 1 `(3, 13, 3, 19)` and added Ian's Skill 1 co-op damage bonus (`23531665`, `+1%..+10%` at Lv 1–10).
  - **Skill 2 (`1048962`)**: Updated geometry to match Sehee's Skill 2 `(5, 13, 5, 19)`, replaced fixed flat Atk reduction with a percentage Atk reduction scaling from `-10%` to `-30%` at Lv 1–10, and added co-op Final Skill Power scaling from `+10%` to `+25%` at Lv 1–10.
  - **Skill 3 (`1048964`)**: Updated geometry to match Lance's Skill 2 `(2, 0, 3, 8)` and added co-op Final Skill Power scaling from `+10%` to `+25%` at Lv 1–10.
  - **Passive (*Knighthood*, `1048963`)**: Preserved the native `+10%` damage bonus against debuffed targets (`0x10018105` on the passive itself instead of duplicating it across active skills) and replaced incoming crit damage reduction (`26742786`) with `+20%` co-op attack damage (`0x10018103`) and `-5%..-25%` incoming hit damage reduction while at least 2 allies remain alive (`0x10018104`).
  - **Awakening (*Destiny Lance*, `0x100185`, when combined with `--alex-awakening` / `12.01`)**: Added a permanent 1-cell Thornbush terrain transformation centered on the Boss's post-swap destination cell (`MovingType.Thornbush = 5`, `_turnStart = 0`, `_turnEnd = 99`) via `Hook 5b` (`GameStage$$ChangeTileType` on `target._orgPositionTile`), keeping single-target unconditional Boss swap (`0x10018501`, `21172225`, `_skillEffectRange = 0`) and updated localization across all 8 languages.
  - Added [`core/alex_rebalance.py`](core/alex_rebalance.py), inspector verification (`inspect_alex_rebalance_assets`), CLI/GUI parity (`--alex-rebalance`, `var_alex_rebalance`), and unit tests in [`tests/test_alex_rebalance.py`](tests/test_alex_rebalance.py).
  - Documented the complete client/server rebalancing methodology and Alex benchmark in [`docs/SKILL_REBALANCE_GUIDE.md`](docs/SKILL_REBALANCE_GUIDE.md) and promoted [`tools/lab_alex_skill_rebalance.py`](tools/lab_alex_skill_rebalance.py) to a thin CLI wrapper around `core.alex_rebalance`.

## [2.5.48] - 2026-11-18

### Changed

- Updated Feature 07.07 (`--guild-raid-skills-max`): **Absolute Protection** (`536870915` across all 8 `guildskillinfo*.unity3d` client bundles) now also sets `_effect03Id = 1048581, _effect03Target = 1`, restoring **100% max MP** to all allies alongside its 100% 1-hit DR (`1048579`) and 100% max HP heal (`1048580`).

## [2.5.47] - 2026-11-18

### Added

- Feature 07.07 (`--guild-raid-skills-max`) maxes the remaining three Guild Raid skills in `guildskilldata.unity3d`: Guild Shelling (`1048577` -> 1,000,000 flat boss damage), Absolute Protection (`1048579` -> 100% 1-hit DR clamped at `1.0`, `1048580` -> 100% maxHP heal), and Combat Support (`1048580` -> 100% maxHP heal, `1048581` -> 100% maxMP restore shared across Shelling/Fire Support/Combat Support, `1048582` -> up to 20 removable debuffs dispelled).
- Feature 07.08 (`--guild-raid-boss-no-counter`) sets `_car = 0.0` (0% counterattack rate, down from `300` / 3% inherited from `CreatureData._baseCar`) across all 70 Guild Raid boss rows (`400-01`..`400-07` host and spawn levels 1..9) in `monsterdata.unity3d`.

### Changed

- Upgraded Feature 05.05 (`--single-gem-fang`): spending one Dragon Fang (`0x7F5148`) on any locked equipment gem slot now hooks `GemStateAccess::mutate_equipment_hole` (`0x8ADE80` -> `0xB2AD10`) to unlock all three gem slots (`hole_pos` `1`, `2`, `3`) at once while preserving any already-open hole and its socketed gem (`gem_code_attr`), keeping the `0x1DCACEC` client bag check bypass.

### Fixed

- Feature 08.06 (`hero_exp_cap`, always-on built-in fix): hooks all three battle/expedition EXP addition sites (`0x80963C` stage, `0x81831C` Tower of Dawn, `0x945E30` expedition) to cave `0xB2AD70` (`creature_max_total_exp_for_level_json` `0xA245DC`), and forces `70` at `0x902008` in `creature_level_max_value_json` when `"level_max"` < `70`, preventing Lv71+ EXP overflow and unlocking Limit Break (`70 -> 72`) for already-overflowed un-transcended 6★ heroes.
- Unknown Paradise Mobile Repair Shop (`WORLDBOSS_RESULT_EVENT` event `10002` at `0x75F6C0`): stopped overwriting `0x75F6C0` (`row_type == 2`) with a type-3 reward row in `apply_mode_drops_x10` (and restores older patched binaries back to stock), keeping `worldboss_travel_repair_offer` and `Instant Repair` working after World Boss battles while preserving daily `500 + 500` Kraken Scales via `0x8E69F4` -> `0xB2AB00`.

## [2.5.46] - 2026-11-18

### Added

- Feature 07.06 (`--guild-raid-fire-support`) updates Guild Raid Fire Support (`536870914`): sets effect `1048578` in `guildskilldata.unity3d` to `_value01=1.0, _value01Factor=0.0, _value02=0.0, _value02Factor=0.0` (100% maxHP minion damage ignoring DR across all turns) and installs a runtime IL2CPP hook at `Player$$ExecuteReservedLordSkill+0x2b4` (`0x018E7060`) via `0xAB335C` -> `0xB2ABC0` so active/reserved Fire Support with full energy holds across even UI turns and auto-fires at the start of odd UI turns (`1, 3, 5...`), leaving all other guild skills on normal immediate timing. Validated live on emulator.

### Changed

- Unknown Paradise (World Boss, part of `--mode-drops-x10` / `01.06`): daily attack rewards are fixed at 500 + 500 Kraken Scales (`0x8E69F4` -> `0xB2AB00`), and weekly/final rank & grade rewards (`0x75EB90`, 22 rows, plus matching `worldbossreward*.unity3d` client datatables) are multiplied by 10x.

### Documentation

- Add a Project Scope statement (offline game preservation of a discontinued title, personal single-player use) and reverse-engineering output hygiene rules to internal contributor guidelines: verbose disassembly and hex output is kept out of summaries, plus a dated-handoff recovery protocol for provider-side content-filter blocks.

## [2.5.45] - 2026-11-16

### Added

- Feature 12.01 (`--alex-awakening`) adds Alex's original 5★→6★ Awakening and Destiny Lance in the new **Original hero modifications** section: updates the client evolution and 26 localized/shared skill tables, embedded server evolution and skill rules, and reference-verified client targeting/swap hooks (Giga-break jump, boss-only manual selection, Auto boss targeting, and no-boss availability). Validated visually on device in Guild Raid (Auto and manual); release builds suppress DEV skill telemetry.

### Documentation

- Document the Alex Awakening and Destiny Lance architecture, code-cave reservations, verification evidence, and the Original hero modifications section in [HERO_AWAKENING_GUIDE.md](docs/HERO_AWAKENING_GUIDE.md), [PATCH_SPEC.md](docs/PATCH_SPEC.md), and [CODE_CAVES.md](docs/CODE_CAVES.md).

## [2.5.44] - 2026-11-15

### Added

- Feature 02.09 adds unlimited Evan and Alex gene offers for 5 event coins and 1 Honor medal, respectively, and increases the remaining Honor Shop Diamond bundle from 60 to 100. Device validation is pending.

## [2.5.43] - 2026-11-15

### Changed

- Feature 04.04 now guarantees the top-quality row instead of only biasing the draw: the rune option table (`0x6ED510`) is rewritten so each pool's highest-`_quality` rows carry the whole pool weight and every other row drops to zero. Rune rolls land on the maximum value every time, and combined with 04.03 they never land on a fixed-value attribute.

## [2.5.42] - 2026-11-15

### Fixed

- Feature 03.05 now also rewrites the option picker's zero-weight fallback (`0x9A2AAC`): a pool whose rows are all flat returns no option instead of falling back to its best-quality flat row, so the flat attributes stop reappearing after their weights are zeroed.
- Feature 04.03 now zeroes the flat `_weight` rows in the client `runeoption.unity3d` table too, matching the server-side `kFwtRuneOptionRows` filter.

## [2.5.41] - 2026-11-15

### Added

- Feature 03.11 lets one appropriate hammer complete the current equipment transcendence tier to +15, +20 or +26; the confirmation and stat preview reflect the target.

## [2.5.40] - 2026-11-15

### Added

- Feature 02.08 changes Lucky Costume Special Boxes 3 and 4 to give one copy of every eligible costume the player already owns, with up to 10 purchases per package per day and batch collection from the shop mailbox.
- Feature 02.07 adds Mythical Stone to the Event Shop for 50 event coins, with a daily limit of 100, and sets the remaining Balance Jade offer to 20 purchases per day.

### Fixed

- Signature inspection now resolves relative APK paths before invoking apksigner on Windows network workspaces.

## [2.5.39rc3] - 2026-11-14

Test build that adds the guaranteed, discounted +12..+15 rune upgrades to the
rc2 feature set.

### Added
- 04.05: rune upgrades +12→+13, +13→+14 and +14→+15 always succeed and
  charge a tenth of the gold, and the guaranteed one-step +12 price now
  shows and charges 95,060 instead of 950,600 (client price hook).

## [2.5.39rc2] - 2026-11-14

Test build with the max-quality option rolls (03.02 reworked) and the flat
hero limit-break price (06.09). Mercenary gem bonuses, rune-upgrade discounts
and the separate translation build remain in progress.

### Added

- Feature 06.09 `limit_break_cost_fixed`: every hero limit break costs a flat
  1,000,000 gold and 100 Balance Jade, in the server table and in the client
  `limitbreakcost.unity3d`. It ships in `--all` and is mutually exclusive with
  the 90% discount (06.06), which now defaults to off.

### Changed

- Feature 03.02 now biases the option-roll table itself: each pool keeps only its
  top-quality rows, so potions, granted gear and re-rolls all produce the maximum
  value for the attribute and the equipment grade. The old mastery-bias words are
  no longer written because that path bypasses locked attributes.

## [2.5.39rc1] - 2026-11-14

This test build includes the guild loading fix. Equipment pink-roll bias,
mercenary gem bonuses, rune-upgrade discounts and the separate translation
build remain in progress.

### Changed

- Feature 04.03 also excludes fixed-value rune attributes while its quality
  factor is enabled; the reference table and inspector cover all 3,808 rows.

### Fixed

- Feature 07.03 preserves JSON `null` when the configured mercenary has no
  costume, avoiding an infinite battle loading screen. Missing or invalid
  weekday heroes fall back to the selected guild mercenary. Validated with the
  supplied save in practice mode and with an isolated missing-weekday scenario.
- Feature 02.06 discounts nine additional category-6 server coin prices and
  adjusts the separately assembled 20,000-coin item. The emulator's assembled
  response was verified; purchase debit remains untested.

## [2.5.38] - 2026-11-14

### Changed

- Organize GUI patch options into numbered thematic groups and add a matching
  [feature catalog](docs/FEATURE_CATALOG.md) with stable IDs, CLI flags and option fields.
- Make the configuration column scrollable so development, device and build
  controls remain reachable at the window's minimum size.

## [2.5.37] - 2026-11-14

### Fixed

- Reject unusable save backups and report timed-out installations as unknown.
- Refuse builds with missing required resource archives; inspect every supported
  localized shop table and the client +10 upgrade table along with server patches.
- Verify APK signatures with `apksigner` and compare requested LAN endpoints and
  rune quality values. Release packaging and registration verify APK contents
  and signed build identity, including after a file is renamed.
- Resolve native file locations from the input ELF's `PT_LOAD` segments, including
  development helpers; fail closed for malformed or unsupported mappings.
- Make the resource-repack unit test independent of an apktool download.

- **Friend/Ancient Coin shop purchase crash.** The event-shop lifetime-counter
  hook returned through the previous function's epilogue instead of the
  `shop_buy_count_for_code` epilogue (`0x880A1C`), corrupting the stack during
  `all_daily_counts_for_client_json`; buying from those shops killed the
  process. The cave now returns through the correct epilogue.
- **Daily Event Shop Limits now cover the event-period rows that stayed
  blocked after 24 hours.** Every `limit_type=4` row is now converted to daily
  (1,423 rows total), and the lifetime `shop_buy_counts` lookup is bypassed for
  event-shop codes (`699xx`/`703xx`).

## [2.5.36] - 2026-11-14

### Added

- **One Modification Stone per equipment option change
  (`--equipment-single-mod-stone`).** The stock formula charges 1 stone with
  0-1 locked lines, 2 with two locks and 4 with three locks. The embedded
  server helper now returns 1 for every lock count, and a post-covault client
  hook rewrites the lock-count argument in `EquipmentOptionChangeGUI`, so the
  cost label and the client inventory check both accept one stone.
- **Percentage-only equipment option rolls
  (`--equipment-percent-options`).** Every flat `randoptiontable` row
  (`_valueType=1`, e.g. +100 Crit, +50 HP) has its six roll weights zeroed;
  the percentage rows (`_valueType=2/4`, e.g. +10% Crit Rate, +2% HP) keep
  their weights. The embedded server table `fwt_randoption_rows`
  (`0x621E60`, 1856 rows x 40 bytes) gets the same treatment for the flat
  option groups (296 weights), so the server cannot draw a flat row either.
  A fresh install extracts the patched client table; an existing install
  keeps the previously extracted
  `/sdcard/Android/data/com.nexon.fwar/files/Resources/datatable/randoptiontable.unity3d`
  until the app data is cleared or that file is replaced.
- **+10 equipment upgrade always succeeds
  (`--equipment-upgrade-10-guarantee`).** The embedded server roll reads the
  fail-probability table at `0x6BC118`; the +9 entry (`0x6BC160`, 595082) is
  set to 0 so the deterministic roll returns success before hashing. The
  client `equipsuccessprobability` row for `_baseEquipEnchant=9` also gets
  100000 on all six grade columns. +0..+8 and +10 -> +11 keep their stock
  probabilities; +21..+26 stay in `--upgrade-no-fail-above-20`.
- **Validated on device (2026-11-13):** one stone shown and charged with two
  locked lines (server response kept the locked lines and charged exactly one);
  a re-roll produced four percentage attributes; ten +9 items reached +10 with
  ten direct server requests, while three +10 -> +11 requests still failed.

## [2.5.35] - 2026-11-13

### Changed

- **Feature catalogue cleanup.** The demoted features were removed from the engine, CLI, GUI,
  inspector and distribution report: recycling by tickets, Select All 4★/5★, equipment option
  mastery factor, both 50% Limit Break profiles, the 3-hour Mana Stone Compactor, the 3-hour
  Energy Flask and Stamina Cashback. The 90% Limit Break profile is the only Limit Break
  option left.
- **Gold Cylinder and Mana Stone Compactor are now x10 multipliers.** The Gold Cylinder hook
  computes `level*100000 + 100000` (was `level*10000 + 10000`); the Mana Stone Compactor scales
  both reward bases from `level*20 + 60` to `level*200 + 600`.
- **Phantom win boxes are a built-in bug fix.** `battle_has_mapped_coocoo_box` is forced to
  report `is_win_box: false` in every build; there is no `--no-win-box` flag anymore. The
  embedded server never inserts a box item, so the guard only hid phantom result rows.
- **Event shop client tables match the server rules.** `shopdata*.unity3d` now sets the gene
  rows to `limit_type=255 / purchase_count=255`, converts event `limit_type=3/4` rows to daily
  (`1`), and discounts `_coinPrice` in campaign (category 6) and event (category 11) rows.
  `shopcontentsdata*.unity3d` discounts `_purchaseNum` and converts the same limit types. The
  patcher verifies each table's sentinel before writing, so a second pass is a no-op.

### Fixed

- **Unlimited Event Shop Genes no longer locks after the first purchase batch.** Both the
  embedded server catalog and every localized client `shopdata` row are unlocked; the server
  keeps `limit_type=255` and the client no longer carries the old type-1/3 row that required a
  restart.
- **Campaign shop discounts reach every campaign counter.** Friend-point rows, Ancient Coin
  and Guild Raid `_coinPrice` rows (category 6) and the event coin rows (category 11) are
  discounted by 90%; the previous pass only covered friend prices and category 11.
- **Daily Event Shop Limits are applied by the release line.** `--all` enables
  `--event-limits-daily`; the feature was missing from the eight-flag release list used by
  2.5.30–2.5.34.
- **6★ recycling no longer biases the pieces.** After the per-set split the cave distributes
  each set's weight across every selected piece (`divmod` per code, remainder spread over the
  rows), so all codes of a selected set have the same drop weight instead of the first pieces
  absorbing the remainder.
- **One Dragon Fang per slot also relaxes the client inventory gate.**
  `EquipmentGemsGUI.OnDragonFangButtonPressed` compared the slot index with the owned fang
  count (slot 2 required two fangs, slot 3 required three). A post-covault hook rewrites that
  branch (`0x1DCACEC b.le` -> `b`) at startup; the server still charges one fang, so the client
  no longer demands extra copies in the bag.

### Investigated

- **Phantom win box origin.** The stock offline responder already contained
  `battle_has_mapped_coocoo_box`; no patch introduced the function. The phantom rows came from
  the payload advertising a box while `coocoobox_reward` stayed `null` and the reward list
  empty. The fix is kept as an unconditional bug fix rather than a user-facing option.

## [2.5.34] - 2026-11-12

### Fixed

- **The whole `--all` feature set is back in the build.** Releases 2.5.30 through 2.5.33 were
  built from an explicit list of eight flags instead of `--all`, which silently dropped every
  feature the umbrella enables — recycling stopped granting 6★ equipment (reported from play),
  and with it went single black hammer, single dragon fang, 10x campaign gold/XP, gene drop
  priority, no equipment drops, event shop discount, unlimited event genes, daily event limits,
  3h laboratory, energy flask x10, 10x campaign event coins, 64-bit guild raid scores, gem
  mining x10, devil soul x10, mode drops x10, guild raid rewards x10, the arena fixes and the
  option/rune quality rows. `--all` sets 41 fields; the release line is now `--all` plus the
  flags it does not cover (`--no-win-box`) and the two numeric factors.

## [2.5.33] - 2026-11-12

### Fixed

- **The raid mercenary is the hero configured for today (`--guild-raid-mercenary`).** The game
  keeps one hero per weekday in `guild_hired_soldier_info` (`mon_crs_idx` … `sun_crs_idx`) and
  writes that map when the mercenary is set; `hired_soldier_idx` does not move, so changing the
  mercenary of the day left the previous hero on the field — reported after swapping today's
  mercenary and still getting the old one. The cave now reads the weekday map first: the weekday
  comes from the server clock, `((server_now_epoch(state) / 86400) + 4) % 7` (1970-01-01 was a
  Thursday, so 0 is Sunday), the matching `<weekday>_crs_idx` is read with
  `raw_object_field(state, "guild_hired_soldier_info")`, and `hired_soldier_idx` is kept as the
  fallback for saves with no weekday entry. Everything else — equipment, costume, runes, soul
  gears — still comes from the live ownership lists, so no registration step is needed.

### Note

- The mercenary the game itself hires is a snapshot of the deck registered when the mercenary was
  configured; on this save that snapshot is from 31/10 and nine of its fifteen items are by now
  equipped on other heroes. The patch ignores it on purpose.

## [2.5.32] - 2026-11-12

### Added

- **The guild raid hires your own mercenary, with everything he is wearing
  (`--guild-raid-mercenary`).** The embedded server answered the hire with a mirror row
  shipped inside the APK (level 120, code `00120646`), so the raid always showed a
  stranger. The projection is now built from the player's save: `hired_soldier_idx` gives
  the id, and every ownership list (`creatures`, `costumes`, `equipments`, `runes`,
  `soulgears`) is filtered by `crs_idx`, filling all seven
  `GuildBattleHiredProjection` slots — `hired_info`, `hired_costume`, `hired_equips`,
  `hired_runes`, `hired_soulgears` plus the `all_costumes` / `all_soulgears` lookups the
  client resolves the references against. The substitution is unconditional: in the raid a
  mercenary that already fought a stage cannot be picked again, so any name on the member
  list delivers the player's own unit. The branch at `0x930100` jumps into a cave hosted in
  `itanium_demangle::DtorName::printLeft` (`0xB34860`), generated from AArch64 assembly by
  `tools/gen_merc_cave.py`.

### Fixed

- **A cave could build the whole projection and still be discarded.** The stock function
  marks the projection valid two instructions before its epilogue (`0x9302BC mov w8,#1 ;
  strb w8,[x19]`); jumping straight to the bare epilogue at `0x9302C4` left `+0x00 valid`
  zero and the dispatcher answered `{"ERROR":-101,"msg":""}` with nothing in the log.

### Waiting for a device check

- `--guild-raid-mercenary` was measured, not validated: the payload carries
  `crs_idx=49 code=00130816 level=74`, 15 equipments, costume 77, 3 runes, 3 soulgears,
  88 `all_costumes` and 108 `all_soulgears`, and the raid screen still has to be seen.

## [2.5.31] - 2026-11-12

### Fixed

- Build with `--no-win-box`: the battle result payload no longer advertises a cocoo box the
  embedded server never grants, so the end-of-battle list stops showing box slots that never
  reach the inventory (reported with the stage skip ticket). Carries every patch from 2.5.30
  plus this one.

### Details from 2.5.26 – 2.5.31 Development Cycle

- **Note on lock-safe option boost (later reverted):** the experimental caller gate cave at
  `0xB39860`/`0xB39874` described below was later removed because `[x29, #-0x38]` did not hold
  the locked-option set; `equipment_option_factor` directly patches `weighted_randoption_id_json`
  (`0x9A2AF4`/`0x9A2B14`) and defaults to `0` (`off`) so locked lines stay untouched unless
  explicitly enabled.

#### Fixed (2.5.26 – 2.5.31)

- **The end-of-battle list no longer shows Cocoo Boxes that never arrive (`--no-win-box`).**
  Reported with the stage skip ticket: the result screen listed box slots and an appearance
  count, and the inventory never received anything. The payload's verdict comes from
  `battle_has_mapped_coocoo_box` (`0x8da77c`), whose single caller (`0x80f0d8`) writes
  `,"is_win_box":` followed by the literals `true` (`0x4f04e6`) or `false` (`0x4d5da7`).
  The embedded server hardcodes `coocoobox_reward: null` and `coocoobox_reward_list: []` in
  every response template and no code path inserts a box item into the inventory, so the
  `true` only fed the client's rendering. Rewriting the function prologue to
  `mov w0, wzr ; ret` answers `false` everywhere, which makes the list match the drops that
  actually land. Safe because the function has exactly one direct caller in the library.

- **`tools/dump_fn.py` read `.rodata` and `.data.rel.ro` 16 KB off.** The helper mapped
  every address with one constant delta (`file offset = vaddr - 0x4000`), which is only
  correct for `.text`; the library has four `PT_LOAD`s, so `file offset = vaddr` holds for
  `LOAD1` (`.rodata`) and the delta grows by 0x4000 per load (`.text` 0x4000,
  `.data.rel.ro` 0x8000, `.data` 0xC000). Consequences measured with the corrected map:
  the rune tables decode cleanly — `kFwtRuneRewardTypeRows` at `0x61e134` (17 rows of 16 B:
  `weightNo, weightValue, runeType, slotOnly`), `kFwtRuneRewardRows` at `0x61def0`
  (11 rows of 44 B, 11 ints) and `kFwtRuneAttrsRows` at `0x61e244` (216 rows of 28 B) —
  where the previous session concluded "the stride is not 16 bytes" and stopped. The
  annotator now resolves literals it used to blank out: `0x3dd1e6 → "gacha_weight_no"`,
  `0x5d1aab → "item_count"`, `0x22bf8c → "shop_code"`, `0x548de0 → "contents-shop-rune"`.
  `parse_segments()`/`file_offset()` are pure and covered by `tests/test_dump_fn.py`
  (synthetic ELF plus the real PT_LOAD deltas, `.bss` unmapped).

- **Locked equipment options now survive the first roll (`--equipment-lock-fix`).**
  `EquipmentStateAccess::change_option` (`0xa1832c`) rolls twice: it calls
  `refresh_equipment_options_for_code_json` (`0xa16fb8`), which re-rolls the whole set with
  no lock set and no mastery bonus and writes the result into the equipment record, and only
  then reads `lock_list` from the request and rolls again with the locks. The locked lines
  are restored from the record the first roll just overwrote, so a locked attribute came
  back with a fresh value until the same lock list was sent twice. Measured on the device
  over 50 rolls: 10 violations in 17 rolls where the lock list changed, 0 in 35 where it
  repeated. NOPing the refresh call (`0xa18354`) leaves the locked preset intact and the
  single locked roll writes the record; verified on device, including the transition roll.
  This is a stock-server bug, not a regression of the option-quality patch: it reproduces
  with none of our equipment patches applied.

- **Equipment option boost lock gate *(reverted)*:** an earlier attempt routed both call
  sites (`0x9a15ac`, `0x9a1b74`) through a 20-byte cave that tested `[x29, #-0x38]`
  (`w4 = 450 * N` only when unlocked). Because `[x29, #-0x38]` did not reliably hold the
  locked-option set, that cave gate was reverted; `apply_equipment_option_factor()` sets
  `0x9a2af4` (`w8`) and `0x9a2b14` (`w9`) directly inside `weighted_randoption_id_json`,
  which can take `:mastery-good-pick` and bypass locks (`0` / off by default).

- **Rune box: slot and type roll randomly again, quality stays fixed (`--rune-box-random-roll`).**
  The rune identity in `pick_battle_rune_code` (`0x982c1c`) comes from
  `stable_reward_roll_text` (`0x987454`), a deterministic FNV-style hash of fixed strings
  that the Korean dev added to pin the rune quality and the fourth attribute. Measured
  side effect: nine 4★ box purchases produced nine identical codes. The code itself is
  built by `snprintf("%llX")` at `0x9832e8` — it is **hexadecimal**: `0x31402` =
  slot 3, grade 1, 4★, type 2, where type 0/1/2 is attack/defense/HP. Three purchase
  rounds on the emulator pinned the two levers: rerouting the `-slot` roll (`0x982f04`)
  makes the slot vary, and the type-table loop (`0x983178) reads `x0` without any of the
  four rolls feeding it, so the type has to be seeded at the loop entry. A plain
  incremented counter is not enough — 1, 2, 3 all fall inside the first weight bucket and
  every box came out attack — so the cave now carries a 32-bit **xorshift32** over a word
  kept in the zero-filled padding between `.data` and `.bss` and leaves the mixed value in
  `w0`. `-grade`, `-quality` and `-type` stay untouched: the star never moved because each
  `kFwtRuneRewardRows` row carries its own grade weights (the box row is
  `0, 10000, 0, 0, 0`), which is the dev's deterministic design. Verified on device: five
  purchases produced three distinct slots and three distinct types. The 68-byte cave is
  hosted by `itanium_demangle::DtorName::printLeft` (`0xb3981c`) — the first host tried,
  `__stdinbuf<wchar_t>::imbue`, is reached by the locale setup and crashed the game at
  boot. `--inspect-so` reports `1/1 slot roll rerouted, type loop seeded: True,
  grade/quality still deterministic: 3/3`.

#### Added (2.5.26 – 2.5.31)

- **Equipment options: scale the Lord-mastery quality bias (`--equipment-option-factor N`).**
  `weighted_randoption_id_json` (`0x9a2790`) turns the mastery bonus it receives into a
  probability in 1/10000 units — `q = min(10000, (total*bonus + remaining - 1) / remaining)`
  at `0x9a2b28`, and the good row is granted when `q > hash % 10000` (`0x9a2c78`). Callers
  pass `mastery_level * 30` with the mastery clamped to 15, so the ceiling the game itself
  allows is **450 (~4.5% per roll)**, which is why the potion still rolled average lines even
  after the mastery fix. Both reads of that argument (`0x9a2af4` → `w8`, `0x9a2b14` → `w9`)
  are replaced with a single `movz`, so every path that reaches the picker — potion, granted
  gear, re-rolls — uses `450 * N`, capped at the game's own 10000 (100%). Default in the GUI
  and under `--all` is `N = 10` → 4500 (~45%). Verified with `--inspect-so` on the patched
  library: `Active (w8=4500, w9=4500)`; 19 bytes differ from the release library, in three
  regions.
- **4★ random rune box: roll any of the three rune types (`--rune-box-random-type`).**
  `pick_battle_rune_code` (`0x982c1c`) indexes `kFwtRuneRewardRows` (`0x61def0`, 11 rows of
  44 B) with the shop row's `gacha_weight_no` and filters `kFwtRuneRewardTypeRows`
  (`0x61e134`, 17 rows of 16 B) by that row's `typeWeight`. Every "4-Star Random Rune Box"
  entry (item_code `1131`/`1132`, shop_code `470008`) carries `gacha_weight_no = 9`, and
  group 9 in the type table holds a single row with `runeType 8` — which the picker rejects
  (`cmp w19, #2; b.hi`), so the box could never roll one of the three real types. Rows 11–13
  of that table (groups 10–12, all unreachable for the same reason) are rewritten into a
  three-row **group 9** with equal weights for types 0, 1 and 2 — the exact shape group 0
  uses for a fair roll. `--inspect-so` reports `Active (3/3 rows on group 9)`.
- **`tools/patch_so_device.py`: iterate on the embedded server without rebuilding the APK.**
  A patched APK is ~1 GB and does not install reliably over Wi-Fi, but a dev build that
  only touches `lib/arm64-v8a/libfwt_local_server.so` is a 13 MB file. `build` writes that
  `.so` from the reference APK (instrumentation only by default, no gameplay patches),
  `apply` swaps it into the app's private `lib/arm64` directory with root and keeps a copy
  of the installed library at `/data/local/tmp/libfwt_local_server.so.original`, `revert`
  puts it back and `status` prints sha256/pid/recent `FWTR-DEV` lines. The save under
  `/sdcard/Android/data/com.nexon.fwar` is never touched.
  **Measured with it: the dispatch-log cave cannot run on the MuMu emulator.** With the dev
  library installed the app died right after `offline convenience patches ready`; the
  houdini (ARM→x86) backtrace puts our cave in the frames —
  `#04 libfwt_local_server.so 0xb29f6c → #03 liblog.so __android_log_print+184 →
  #02 libc.so vsnprintf+192` — a SIGSEGV with no tombstone written. The same cave logged
  69 requests on a physical arm64 device, so this is the translator, not the cave: on MuMu
  install a full dev APK or expect the crash. Reverting the library restores the emulator
  (verified: pid alive, 14 `FwtLocalHttp` requests).
- **Response capture + log parser (phase 7).** `--dev-log-response` makes the exit cave
  log the body the dispatcher returns: `dispatch_json_impl` returns its `std::string` by
  value, so at the single `ret` (`0x7ecd68`) `x0` is a `std::string*` with the same
  libc++ layout the entry cave reads, and the line carries the same counter, so request
  and response pair by number (`FWTR-DEV-R-v2.5.26: <n> <json>`).
  `tools/dev_log_parse.py` turns any capture into JSONL plus a per-command timing
  report: it accepts `-v threadtime` and `-v time`, flags bodies cut by
  `--dev-log-limit` and reports counter gaps when logd's ring drops lines.
  First real session (physical arm64 device, Android 15): 69 requests, a 46-55 ms floor
  on nearly every command, with `GET_MY_INFO` 3.64 s, `GET_MAIL_INFO` 1.36 s and
  `GET_MY_GUILD_INFO` 1.08 s standing out.
- **Handler timing (phase 6, `--dev-timing`).** The entry cave samples `cntvct_el0`
  and every `ret` of `fwt_stub_handle_json` (`0x7e3d8c`, `0x7e3f20`, `0x7e3ffc`)
  branches to a cave at `0xb2a1bc` that logs `us = (now - start) * 1e6 / cntfrq`
  on tag `FWTR-DEV-T-v<version>` and replays the displaced `ret`. Hooking the returns
  (instead of wrapping the call in a detour) keeps the cave out of the C++ unwind
  chain, so a handler that throws cannot crash through a frame without CFI.
- **Build marker (phase 5, `--dev-marker`).** A dev build logs its identity once per
  process on its own tag (`FWTR-DEV-BUILD: FWTR-DEV v2.5.26 fp=3f9c1a04 n=39
  flags=...`), where `fp` fingerprints the build recipe (version + patch count +
  enabled instrumentation). `--dev-marker` alone installs a cave that logs nothing
  per dispatch, only the marker. `--inspect`/`--inspect-so` now report a "Dev Build
  Marker" feature, so a dev APK is distinguishable from a release without running it.
- **Hit counter in the dispatch log (phase 4, `--dev-counters`).** The dev log line
  now starts with a per-process counter (`FWTR-DEV-v2.5.26: 1234 {...}`). The
  binary has no free writable memory (`.bss` packed to the last byte, `.data`
  fully covered, `.data.rel.ro` "gaps" are relocation tables, and the unreferenced
  data objects are the game's tables reached through `adrp`+`add`), so the cave
  makes its own page writable once per process via the library's imported
  `mprotect`, gated by a magic byte — the same technique the offline APK author's
  own framework uses. `--dev-log` alone leaves page permissions untouched.
- **Dispatch log cave (phase 3, `--dev-log`).** One branch at the embedded server's JSON
  entry point (`fwt_stub_handle_json`, `0x7e3bd8`) sends execution through a 0x120-byte
  code cave carved inside `itanium_demangle::AbstractManglingParser` (`0xb29ebc`), which
  logs the payload carried in `x1` to logcat under `FWTR-DEV-v<version>` and returns into
  the real function after replaying the displaced `sub sp, sp, #0x90`. `%.*s` truncates at
  `--dev-log-limit` (default 1024; `0` logs the whole body). Every AArch64 encoder needed
  by the cave (`adrp`, `add`, `sub sp`, `stp`/`ldp`, `str`/`ldr`, `movz`) is verified by
  disassembling it with capstone, and the cave itself is executed under unicorn in
  `tests/test_dev_dispatch_log.py` — including register preservation and the branch back.
  A surgical-diff test asserts the dev build changes only the hook word and the cave.
- **Dead-code map and laboratory trap builds (phase 2).** `tools/dead_code_map.py`
  maps which code in `libfwt_local_server.so` is unreachable, combining direct-call
  decoding (capstone), `adrp`+`add` address materialization, relocations and export
  status over a reachability BFS, with per-assumption profiles (`conservative`,
  `demangler-only`, `lan-mode`, `error-paths`). `tools/lab_trap_apk.py` turns a
  candidate into an experiment: it plants `brk #0` in a chosen function and produces
  a signed, debuggable lab APK so a crash proves the code is alive. Results and the
  protocol are in `docs/CODE_CAVES.md`; the ~15 s analysis runs under the new `slow`
  pytest marker.
- **Dev build manifest patch (phase 1).** New `core/axml.py` rewrites the binary
  `AndroidManifest.xml` in place: every dev build gets
  `android:versionName="0.682-dev"` (the string is appended to the manifest string
  pool, keeping all chunks 4-byte aligned) and `--dev-debuggable` flips
  `android:debuggable` to `true` without changing the manifest size. That makes
  `adb shell run-as com.nexon.fwar`, the `--backup`/`--restore` `run-as` fallback,
  JDWP and `log.redirect-stdio` work on a **non-rooted** phone. Validated against
  `aapt2 dump badging`/`xmltree` in `tests/test_axml.py`.
- **Development build (dev instrumentation, phase 0 of 9).** New `DevOptions`
  block behind a `--dev` master switch (`--dev-debuggable`, `--dev-log`,
  `--dev-log-limit`, `--dev-log-commands`, `--dev-counters`, `--dev-marker`,
  `--dev-timing`, `--dev-snapshots`, `--dev-endpoint`, `--lab-traps`) and a
  **Development** card in the GUI with *Telemetry* / *Tools* / *Laboratory*
  groups. Nothing is wired into the binary yet: with the master switch alone a
  dev build is byte-identical to a release build, and a requested-but-unwired
  feature is reported as a build warning. Dev builds are forced to a `*-dev.apk`
  name (CLI, GUI and `tools/create_distribution_zip.py` all refuse dev
  artifacts). See `docs/DEV_BUILD.md`.

#### Fixed (Suite Guard)

- **Stale expectation in the `--all` patch-count test.** `gold_cylinder_fix` is a
  guard patch that legitimately reports 0 sites on the reference build (the
  reference already ships the 21,600 s timer) — the dedicated test asserts 0, but
  `test_reference_all_patch_counts_and_egl_integrity` still expected
  `len(GOLD_CYLINDER_SITES)`, leaving the suite red.

## [2.5.30] - 2026-11-12

### Fixed

- **The boot text is English again.** `--english` (`english_localization`: the C# string
  table bypass, the two localization gates and the Korean UI literals in the native
  library) was left out of the 2.5.28 and 2.5.29 command lines, so the loading screen went
  back to Korean. This build carries it together with every other validated patch.

### Added

- **Hero limit break (Awake) at a tenth of the cost (`--limit-break-cost-tenth`).**
  `CREATURE_TRANSCEND` is handled from `0x82108c`: it validates the creature, reads
  `level_max`, looks the row up in `kFwtCreatureLimitBreakCosts` (`0x756cf0`, 45 rows of
  24 bytes, level caps 70..118) and both **checks and spends** the gold and the material
  count from those same cells (`0x822a48` accumulates, `0x902314` subtracts), so the price
  the player must afford and the price charged can never disagree. Every quantity and gold
  value in the stock table is a multiple of ten, which makes a tenth-off exact. The patch
  validates the table by SHA against the stock digest (so it refuses to run on top of the
  50% variants), divides both columns, and is wired through CLI, GUI, `patch_so_device`
  and the inspector. The cost table is not exposed by any endpoint, so the client keeps
  its own numbers for display.
- **Soulgear enchant always succeeds (`--soulgear-enchant-always`).**
  `SOULGEAR_UPGRADE` has no roll at all — it only charges `2020029` and gold and bumps
  `upgrade_gear`. The roll lives in the **gold-paid** `SOULGEAR_ENCHANT`, which both
  actions reach through `SoulgearGrowthStateAccess::apply` (`0x8b29e4`): there an FNV-1a
  hash over `lord:sg_idx:enchant_cnt:sg_code` is compared against the success/failure
  tables at `0x6bc0c0` / `0x6bc118` (84.75% falling to 6%) and the verdict is materialised
  by a single `cset w8, lo` at `0x8b3b4c`. Replacing that with `mov w8, #1` makes every
  paid enchant succeed. This binary has no `hero mark` opcode, so nothing else was touched.

## [2.5.29] - 2026-11-12

### Added

- Build with the four patches validated on the emulator (options potion boost and lock
  fix, rune attribute quality, rune box slot/type roll) plus the two new server-side
  features: hero limit break at a tenth of the cost and the soulgear enchant always
  succeeding. See `[Unreleased]` for the mechanics of each one.

## [2.5.28] - 2026-11-12

### Fixed

- **Locked equipment options survive the first roll**, the options potion rolls better
  lines again, and the rune box finally varies slot and type. Details of each fix are in
  the `[Unreleased]` section above; this entry marks the build that was validated on the
  device with `--equipment-option-factor 10 --equipment-lock-fix --rune-quality-factor 10
  --rune-box-random-roll`.

## [2.5.26] - 2026-11-11

### Changed

- **Resource archive streaming.** `assets/fwt_resources_v1.zip` is extracted
  and rewritten through temporary files, keeping the ~811 MB nested archives
  out of RAM during the build.
- **Segment-aware offsets.** Internal vaddr→file-offset mapping uses
  `seg_offset()` and the reference ELF segment table.
- **Dead code cleanup.** Removed unused patch constants, `_relocate_cave`, the
  dead labcount helpers, unused theme constants and `FilePathPicker.set_path`.
- **Gold Cylinder guard.** The inspector distinguishes pristine, legacy and
  modified timer words, so the guard can fail on a drifted build.
- Distribution builds now require ~4× the input APK in free disk space.

## [2.5.25] - 2026-11-11

### Fixed

- **Patch engine integrity.** Removed the dormant slot-matched recycling cave
  that aliased the completion cave at `0xB3337C`; added explicit per-feature
  idempotence flags in the free `0xB33414` gap, bounds-checked every raw cave
  write, and refuse to emit an ELF/DEX whose size changed during patching.
- **Second-pass idempotence.** `flask_3h`, `gem_mining_x10`,
  `gem_mining_types`, `gem_level6`, `recycle_six_star`,
  `guild_raid_reward_x10` and the single-site patches now report zero changes
  on an already patched library; `IDEMPOTENT_PATCHES` is a single declared set.
- **Honest output hashes.** `PatchResult.so_sha256`/`dex_sha256` now hash the
  patched output; the input hashes are kept as `input_so_sha256` /
  `input_dex_sha256`.
- **Segment-aware file offsets.** Every vaddr→file-offset conversion now goes
  through `seg_offset()` and the reference ELF segment map, replacing the
  hand-mixed `DELTA_TEXT`/`DELTA_RODATA` convention.
- **Resource archive streaming.** `assets/fwt_resources_v1.zip` is extracted
  and rewritten through temporary files; peak RAM no longer holds multiple
  copies of the ~811 MB nested archive.
- **Dead code cleanup.** Removed unused patch constants, `_relocate_cave`, the
  dead labcount helpers, unused theme constants and `FilePathPicker.set_path`.
- **Gold Cylinder guard.** The inspector now distinguishes pristine timers from
  legacy/modified words, so the guard can actually fail on a drifted build.
- **Recycling set bias removed.** The native `_weightValue` column made four
  6★ sets up to ~31x more likely than the rest. The server table and the
  client `equipreward.unity3d` now split each alchemy group's original total
  weight equally across the sets of its slot (difference ≤ 1 unit), so all
  obtainable 6★ sets have the same chance.
- **Embedded catalog safety.** Event Shop gene/limit replacements now assert
  the match length before writing, and campaign/event discounts use an explicit
  patch flag instead of treating any JSON whitespace as "already discounted".
- **Mode drops no longer rely on data heuristics.** The Dimension hook is the
  authoritative marker, so a second pass cannot skip or double-multiply the
  Nephthys, Lost Island and Sky Library tables.
- **World Boss settlement cave** now executes the original `cmp x2, #1`
  before multiplying, preserving the conditional branch flags.
- **Inspector fail-open checks.** Event discount, daily limits, gene priority,
  crystal skill assets and the DEX backup prompt now require positive
  evidence; duplicate display name for the two Battle Arena fixes removed.
- **Sacred Lands** is now included in the resource-patch gate, so enabling it
  alone actually patches `setitemtable`/`equipselectlist`.
- **Save restore safety.** Restores validate the save schema, create an
  on-device timestamped backup, use a randomized `/data/local/tmp` name and
  verify the copy with `cmp` before reporting success.
- **Lab datatable push safety.** The tool aborts when the device backup fails
  or is empty, never overwrites an existing `.orig`, validates `--cooltime`,
  writes the output atomically and verifies the re-encryption round-trip.
- **APK replacement safety.** `apksigner verify` runs before the output is
  replaced, and the previous good build is kept as `.prev`.
- **CLI correctness.** Mutually exclusive mode/summon/recycling/limit-break/
  stamina groups, `--limit-break-gold-half` is honored under `--all`,
  `--recycle-tickets` overrides the 6★ default, `FWT_SKIP_VERIFY=1` no longer
  skips `--install`, and a build with no feature selected is rejected.
- **ADB safety.** Device ids are validated against `adb devices`, multiple
  ready devices require `--device`, `package_state()` distinguishes
  `unknown` from `not installed`, uninstall happens only after a verified
  build, and a slow install timeout is re-checked with `pm path`.
- **DEX MUTF-8.** String decoding accepts `C0 80` NULs and CESU-8 surrogate
  pairs instead of rejecting valid DEX files.
- **GUI safety.** Closing the window during a build asks for confirmation and
  waits for the current tool; backup/restore/uninstall share a busy guard; the
  log pump survives per-line errors and caps work per tick; duplicate Battle
  Arena labels removed.
- **Distribution ZIP safety.** Rejects secrets/artifacts by extension, uses
  relative path components for exclusions, skips itself, writes atomically,
  and fails when a requested APK is missing.
- **Dependency/docs drift.** `core.version.versioned_output_path` no longer
  treats `2.5.250` as versioned; README, changelog ordering/dates and the
  release date now match `2.5.25`.

### Changed

- CI now auto-marks APK-dependent tests, runs a Windows matrix, measures
  coverage, and installs the analysis/assets extras needed by the tests.
- `requirements.txt` pins the AVX2-free `duckdb==1.5.6`; `dev` includes the
  optional asset/ELF dependencies.
- Ruff/mypy settings tightened (strict markers, `W`/`C4`/`SIM`/`PT`, and
  mypy `check_untyped_defs`/`warn_unreachable`).

## [2.5.24] - 2026-11-10

### Fixed

- **Guild Raid self-mercenary via runtime override (no version bump).** The
  hire list is left untouched (the player is not injected into
  `guild_members`; the guild state stays intact). Instead the server's
  `guild_battle_hired_projection` hook (`0x930100`) now always builds the
  projection from the player's own daily mercenary
  (`infinity_local_hired_soldier_json` + `hired_info_with_transport_identity`
  with the player's lord), ignoring the selected guild member. The client keeps
  the list filter `nop` (`0x1EE5220`). Effect: after choosing any member in the
  hire screen, the battle fields the player's own configured mercenary.

## [2.5.23] - 2026-11-10

### Added

- **Guild Raid self-mercenary client filter removed.** `InventoryCreatureSmall_GuildRaidMercenary.UpdateListMember` compares each guild member's lord with `LordData.get_lordID` and branches to the skip path (`0x1EE5220`: `b.eq 0x1EE531C`), so the player never appeared in the hire list. A post-covault cave (hook `0xAB3380`, cave `0xB336D8`, base from `0xBE3798`) now NOPs that branch, letting the player's own mercenary be listed. Combined with the existing server-side self projection cave (`0xB3367C`) and the manually added membership, the self-mercenary flow is complete.

## [2.5.22] - 2026-11-10

### Fixed

- **Battle Arena save, second gate.** After the defence-count fix the handler
  still returned `-101`: it runs `exact_json_object_field_set` against an
  auth-only schema (`CMD`, `packet_no`, `lord_idx`, `access_code`) while the
  real arena request also carries `attack_teams`, `def_arena_force` and
  `defence_teams`, so the schema check failed before the teams were parsed. The
  failure branch at `0x841AC8` (`tbz w0,#0,#0x841EBC`) is now a `nop`, letting
  the handler parse and store the sent teams.

## [2.5.21] - 2026-11-10

### Fixed

- **Battle Arena team save now succeeds.** With the 2.5.19 client hook the game
  sends `ARENA_SET_ATTACK_TEAM` (eight attack members, four defence leaders),
  but the offline server rejected it with `ERROR_NOT_ENOUGH_JEWELRY` (-101): the
  handler required **eight** values for `defence_teams` in the size check
  (`cmp x8, #0x40` at `0x841BA0`) and in `valid_owned_team_json` (`w2=8` at
  `0x8425A0`). Both sites now expect four (`#0x20` / `w2=4`), matching the
  client payload, so the parsed teams reach the existing store path
  (`arena_attack_teams` / `arena_defence_teams`). Validated on the emulator:
  `ARENA_SET_ATTACK_TEAM` must now return `error=0` and the teams must leave
  `-1`.

## [2.5.20] - 2026-11-10

### Added

- **Guild Raid self-mercenary (`guild_raid_mercenary`) is now complete.** The
  anti-self branch in `guild_battle_hired_projection` (`0x930100`) is no longer
  NOP'd: it branches to a self-projection cave (`0xB3367C`, tail of the shared
  select_all slot) that builds the hired projection from the player's own
  mercenary using the same helpers the guild member list uses for the self
  entry — `infinity_local_hired_soldier_json` (`0xa6af78`) plus
  `hired_info_with_transport_identity` (`0xa6ae64`, kind 2) — writes it to the
  projection `+0x08` slot, sets the valid flag and jumps to the epilogue.
  Non-self selections fall through to the original `0x930104` flow, so hiring
  guild members is unchanged. Costume/equipment slots keep their `null`/`[]`
  defaults (the client uses the player's own data). The cave and the Battle
  Arena cave share the 0xF0 slot with per-range SHA guards.

## [2.5.19] - 2026-11-10

### Fixed

- **Battle Arena team Save fix works and is enabled again.** The 2.5.17 hook
  crashed AppSealing for two stacked reasons: the client RVA was mis-encoded
  (`movz #0xFCC` + `movk #0x1AA6` produced `0x1AA60FCC`, not the intended
  `0x01AA6FCC`), and the write ran during the early startup trampoline. The
  corrected hook runs from the epilogue of the covault permission-finalization
  function (`0xAB337C`, after `covault code permission finalization complete`),
  reads the cached libil2cpp base from the server global `0xBE3798`, and calls
  `patch_words` with `w1 = 0x01AA6FCC` (low `0x6FCC` + high `0x01AA`). Verified
  on the patched emulator: the game boots, the covault finalization completes,
  and client memory at base+`0x1AA6FCC` reads `aa1403e8` (`mov x8, x20`) with no
  crash. Enabled by `--all` and in the GUI; mutually exclusive with
  `--select-all-4-5` (same cave slot).

## [2.5.18] - 2026-11-10

### Changed

- **Battle Arena save fix is now opt-in and marked experimental.** The client
  hook described below is correct in the disassembly (the Save handler throws a
  NullReferenceException when the team manager is null), but installing it at
  startup makes AppSealing's `libcovault-appsec.so` abort with SIGSEGV before
  Unity starts (validated on the patched emulator: 2.5.16 boots, 2.5.17 with the
  hook does not). The feature therefore left `--all` and the GUI default; use
  `--battle-arena-save-fix` only for experiments. The patcher, inspector and
  tests are kept for the follow-up work (apply the hook after the covault
  permission finalization, or find a non-code patch).

## [2.5.17] - 2026-11-10

### Fixed

- **Battle Arena team Save works again (`--battle-arena-save-fix`).** The client's
  `ArenaAttackTeamListGUIInInventory.Init` stores its team manager at `+0x60`
  only when an il2cpp type-hierarchy check passes; offline the check fails and
  the manager stays **null**, so `OnOKButtonPressed` throws a silent
  `NullReferenceException` and the Save button appears dead. A runtime
  `patch_words` hook (installed through the same trampoline used by
  `select_all_4_5`) rewrites client RVA `0x1AA6FCC` (`csel x8, x20, xzr, eq` →
  `mov x8, x20`) so the manager is always stored. Enabled by `--all` and in the
  GUI; mutually exclusive with `--select-all-4-5` (same installer slot).

## [2.5.16] - 2026-11-09

### Added

- **Gems Level 6 (`--gem-level6`).** The lobby gem table at `0xBA8478` points
  to the nine level-1 gem code strings (`16781` .. `96781`, attributes 1..9).
  The gem level is the last digit of the code, so the patch rewrites it from
  `1` to `6` (`16786` .. `96786`): every gem obtained (mining) or bought
  (20-crystal roll) in the lobby gem screen is now level 6, keeping the same
  attribute. Nine single-byte `.rodata` edits, enabled by `--all` and in the
  GUI; verified by the inspector (9/9 codes at level 6) and **validated in the
  lobby gem screen on 2026-11-09** (gems obtained/bought came as level 6).

## [2.5.15] - 2026-11-09

### Added

- **Sacred Lands set (group 4028) added to the slot-4 recycling pool.** Its
  quality-5 pieces are `16860423` Uku Uka (weapon), `33834247` Breechclout and
  `50873607` Oma (all `_equipGrade` 4, support-type only). Slot 4 now has 45
  pieces. The Tower of Dawn sets (ticket list `10010`, three entries) stay
  tower-exclusive and are intentionally not part of the recycling pools.

## [2.5.14] - 2026-11-09

### Fixed

- **Recycling pools now follow the 6★ set selection ticket list.** The
  authoritative list of obtainable 6★ sets is `equipselectlist` list `10009`
  (the ticket that the mileage summon grants): **66 sets / 198 pieces**, not the
  previous 26. The 145 hero-exclusive sets (`setitemtable`
  `_setPreconditionid == 101`, "Deimos only"/"Ragna only"/...) stay out; the
  class-restricted sets (62-69, "Attack-type characters only" etc.) are valid
  and remain. Each list piece is mapped to its quality-5 counterpart (golden
  six-star display) and split by slot (`_equipGrade`): slot 1: 36, slot 2: 45,
  slot 3: 39, slot 4: 42, slot 5: 36.

## [2.5.13] - 2026-11-09

### Fixed

- **Recycling rewards are now slot-matched.** `_equipGrade` is the equipment
  **slot** (1..5), not the star level; 2.5.9-2.5.12 filtered the pool by
  `_equipGrade == 5`, so every reward was a slot-5 piece. The reward table now
  uses **five 6★ pools, one per slot** (quality 5 + secret grade 3, the golden
  six-star display):
  - slot 1: 57 pieces, slot 2: 63, slot 3: 192, slot 4: 78, slot 5: 174
    (564 total, spread over the 26 generic 6★ sets);
  - group `0x65+N` (normal) and `0x6A+N` (final) receive the slot-N pool, so
    filling the slot-N bar always rolls a six-star piece of that same slot
    (weapon/shield/accessory still random).

## [2.5.12] - 2026-11-09

### Changed

- **Recycling 6★ pool now covers every generic 6★ set.** The pool grew from the
  vanilla 10 sets (30 pieces) to **26 sets / 390 pieces** (the 32 hero- or
  condition-specific sets from `setitemtable` `_setPreconditionid != -1` are
  excluded, as requested). All pieces are grade 5 + secret grade 3 and the
  rotation offset is 0 (no reference row already holds its target code), so the
  first pass still changes exactly 873 rows.

## [2.5.11] - 2026-11-09

### Fixed

- **Recycling reward is always 6★ and random again.** Instead of forcing a
  single code, the 873 alchemy reward rows (groups 102-111) now receive the
  game's own 30-piece 6★ pool (grade 5 + secret grade 3, already present in
  group 106: 10 weapons, 10 shields/armors and 10 accessories across ten 6★
  sets). Every capsule roll therefore yields a random 6★ piece while keeping
  the vanilla roll and slot variety. The rotation offset (3) is chosen so the
  first pass changes exactly 873 rows and the second pass changes none.
- **Select All 4★/5★ is no longer part of `--all`.** The client hook broke the
  recycling screen's Select All (it re-delivered the pending capsules and
  raised the alchemy-gauge error), so `select_all_4_5` is now opt-in via
  `--select-all-4-5` (experimental) and off in the GUI.

## [2.5.10] - 2026-11-09

### Fixed

- **Recycling 6★ reward is now slot-matched.** The 2.5.9 patch rewrote all 873
  alchemy reward rows to the same Absolute Gavel, so every completion gave an
  identical weapon. A cave at the pick result (`0x89D088`, returns to
  `0x89D08C`) reads the recycled equipment code from the item struct
  (`string at x19+0x20`) and replaces the reward with a 6★ piece
  (grade 5 + secret grade 3) of the SAME slot. The pool at `0xB333C4` holds two
  pieces per slot:
  - slot 1: `16863619` Absolute Gavel of Defense, `16863507` Carnage Scythe;
  - slot 2: `33837461` Absolute Aegis, `33837334` Gold Dragon Armor;
  - slot 3: `50811273` Necklace of Endurance, `50549121` Firmament Bracelet.
  The choice within the slot uses the last digit of the recycled code, so
  recycling different pieces varies the reward while keeping the slot.

## [2.5.9] - 2026-11-09

### Added

- **Recycling grants 6★ equipment** (`recycle_six_star`, now the `--all`
  default). The native completion pick (0x9A2FB8) selects from
  `kFwtEquipRewardRows` by `0x65/0x6A + grade` (groups 102-111, 873 rows). The
  option rewrites only the `_equipCode` of those rows (server `.rodata`
  0x639760 and the client `equipreward.unity3d`) to **16864643 Absolute Gavel
  of Defense**, a grade-5 item with `_secretegrade` 3 (the 6★ tier). The native
  grant, response append and alchemy point accounting are untouched, so
  recycling behaves exactly like vanilla except for the reward. CLI
  `--recycle-six-star`, GUI checkbox and inspector entry.

### Changed

- `--all` now enables `recycle_six_star` instead of the experimental
  transcendence-ticket cave. The ticket path (`--recycle-tickets`) remains
  available but is marked experimental and is mutually exclusive with the 6★
  reward.

## [2.5.8] - 2026-11-09

### Fixed

- **Recycling tickets were never delivered to the client.** The completion
  trampoline called `grant_item_json` into its own scratch buffer and jumped to
  the cleanup at `0x89D238`, skipping the native response append
  (`0x89D154..0x89D1A0`). It now writes the `ItemInfo` into the native slot
  (`sp+0x1e0`) and returns to `0x89D154`, so the ticket is both stored in the
  state and published in the response items.

## [2.5.7] - 2026-11-09

### Added

- **Guild Raid Rank Rewards x10** (`guild_raid_reward_x10`). The daily and
  weekly guild-raid rank reward mails (item `150001`, gold and the secondary
  reward) are multiplied by 10. Enabled in `--all`, CLI
  `--guild-raid-reward-x10`, GUI checkbox and inspector entry.

## [2.5.6] - 2026-11-09

### Fixed

- **Energy Flask infinite collection.** The `flask_3h` datatable rewrite made
  the client offer 8 three-hour windows (including 15-18h) while the server's
  window guard in `laboratory_use_fields` only accepts 12-15h and 18-21h.
  Collections outside those windows were silently discarded (the state kept
  `use_count` at 0), so the flask stayed available and could be used
  indefinitely. The Energy Flask windows are no longer rewritten;
  `flask_3h` now only changes the Mana Stone Compactor timer to 3h.

### Added

- **Energy Flask x10 Stamina** (`energy_flask_x10`). The free stamina grant in
  `laboratory_use_fields` (`0xA65648`, `add x0, x19, #0x64`) now awards 1,000
  points instead of 100 on every collection. The original 12-15h/18-21h
  windows and the native use-count accounting are preserved. Enabled in
  `--all`, CLI `--energy-flask-x10`, GUI checkbox and inspector entry.

- Decide whether to keep the experimental stamina cashback companion or
  replace it with a server-side result-handler patch.
- Add automated runtime smoke tests for the GUI and ADB flows.
- Refine recycling so the alchemy point item count is consumed per completion;
  the 2.5.4 cave delivers tickets, but the accumulated points are not spent yet.

## [2.5.5] - 2026-11-09

### Fixed

- **Coocoo Level x2 after the Pit of Nephthys reset.** Extend
  `coocoo_level_x2` to the 702xxx tier (30 stage rows total, up from 20). The
  post-reset path uses the 702 table, which previously stayed at level 220.
  The final stage of the 702 tier now drops level-440 coocoos as well.
- **Ancient Coins / campaign shop discount.** Verify the `shop_content: 5`
  rows and raise the campaign discount from 50% to 90%
  (`ceil(price * 0.1)`, minimum 1) across all 94 campaign items. The Ancient
  Coins rows use `price_code` + `price_count`; the server purchase handler
  reads the patched `price_count`. Runtime check: `SHOP_BUY_CONTENTS` `5209`
  charged 90,000 gold instead of 900,000.
- **Battleship Parts upgrade cost.** Raise the Unknown Paradise battleship
  part discount from 50% to 90% (41 non-zero int64 costs,
  `ceil(cost * 0.1)`). The reference part 1 level 1→2 cost drops from 5,000 to
  500 gold.
- **Gem upgrade gold fee.** Add `gem_upgrade_gold_half` (CLI
  `--gem-upgrade-gold-half`, GUI checkbox, inspector entry, included in
  `--all`). `GemStateAccess::graft` now subtracts half of the client-provided
  `fee_gold` at `0x8ACA6C`, leaving the duplicate/consumable gem cost intact.

### Changed

- GUI, CLI and inspector labels updated from 50% to 90% for the campaign shop
  and battleship parts; the Coocoo Level x2 label now says 30 stages and
  includes the Pit of Nephthys tier.
- `expected_feature_keys` and the patch-count tests cover the new
  `gem_upgrade_gold_half` feature.

## [2.5.4] - 2026-11-09

### Fixed

- **Battle Arena / Battle of Honor PvP team save.** The client sends the four
  teams as eight members, but the offline server stores only the four team
  leaders. `REQ_REGISTER_PVP` and `SET_DEFENSE_TEAM_PVP` now compact each
  eight-value vector to its leaders before validation, so all four groups of
  two persist.
- **Equipment recycling.** The 2.5.2 implementation filled reward tables
  `102`..`111`, which are not the tables used by the runtime alchemy selector,
  and read `w28` after it had been overwritten by the reward-string length.
  The new implementation removes the wrong table fill, captures the real 1..5
  grade before the overwrite, forces the native reward pick to return a valid
  dummy row, and grants the class/Ultimate transcendence ticket from the
  completion trampoline. Select All no longer corrupts unrelated rewards.

### Added

- **Gem Type Restriction.** Gem-mining rolls now pick only from MP (2),
  Counter Rate (6), Counter Damage (7), Dodge (8) and Hit Rate (9). HP, ATK,
  DEF and CRIT (1/3/4/5) are already sold as level-6 gems in the Special
  Beginner Package. Included in `--all`, CLI `--gem-mining-types`, GUI checkbox
  and inspector.
- Version bumped to `2.5.4`.

## [2.5.3] - 2026-11-09

### Fixed

- **Energy Flask was always active.** The `flask_3h` patch used to branch
  directly from `0xA655C8` to the laboratory success path, bypassing the
  cooldown and use-count checks. The original `cmp w22, #2` is restored, the
  Mana Stone Compactor's three timer sites are set to 10,800s (3h), and the
  Energy Flask keeps its 3-hour daily windows from
  `laboratorytimezone.unity3d`. The Gold Cylinder remains at 6h.

### Added

- **Battle of Honor rank points x2**: the existing `mode_drops_x10` feature
  now also doubles the rank points earned on a PvP victory (30-40 -> 60-80)
  via a trampoline on `pvp_score_delta` at `0x95563C`; losses are unchanged.
- **Gems x10 (Mining)** (`gem_mining_x10`): the gem-mining count site at
  `0x8AB110` branches to a cave that changes the grant from 1 to 10. Every
  gem-mining roll, including the 20-crystal paid roll, awards 10 gems of the
  same rolled type. Included in `--all`, CLI `--gem-mining-x10`, GUI checkbox
  and inspector.
- Version bumped to `2.5.3`.

## [2.5.2] - 2026-11-09

### Changed

- **Recycling now grants transcendence-ticket items instead of equipment.**
  The server-side bar-completion handler (`0x89D150`) is redirected to a
  trampoline that grants one item per completed bar:
  - normal completion: class I–V equipment transcendence ticket
    (`130001`–`130005`, matching the alchemy grade);
  - final/full-bar step: Ultimate Transcendence Ticket (`130006`, the black
    hammer used for +16..+20).
  A second trampoline at `0x89CEF8` saves the native reward-table selector so
  the completion code can distinguish the final step. The alchemy reward tables
  are filled with a valid hammer row only so the native pick succeeds; the
  selected equipment is never granted. Alchemy points and bar progression are
  untouched. The old `equipreward.unity3d` asset rewrite and the green Past
  Breaking Hammer are removed.
- The CLI flag is now `--recycle-tickets` (the old `--recycle-hammers` remains
  as an alias). GUI and inspector labels were updated.
- Version bumped to `2.5.2`.

## [2.5.1] - 2026-11-08

### Fixed

- **Equipment recycling gave 5★/6★ pieces instead of the common hammer.**
  Tables 102–103 (alchemy grades 1–2) used equipment code `16864643`, whose
  Korean name is "금의 망치" but which `equiptable` defines as the 5★ set
  weapon **Absolute Gavel of Defense** (`equipKind` 1). It has been replaced
  by the real common hammer, **Ruby Hammer** (`16921863`, 루비 해머,
  `equipKind` 2, grade 3). Black Dragon's Hammer IV (`16930082`) and Past
  Breaking Hammer (`16930193`) remain unchanged. The server
  `kFwtEquipRewardRows` and client `equipreward.unity3d` are both rebuilt.

### Changed

- The `Missing required packaging tools` error now lists exactly which binaries
  are missing and explains that `pip install` does not provide `zipalign`,
  `apksigner` or `keytool`. It points to `ANDROID_HOME`/`JAVA_HOME`,
  `scripts/setup-linux-toolchain.sh` and the README troubleshooting section.
- Added `python fwt_patcher.py --check-tools`, a preflight report for the
  `zipalign`, `apksigner`, `keytool` and `adb` paths plus the optional Python
  modules (`dotenv`, `UnityPy`, `cryptography`).
- README now explicitly separates Python requirements from the Android
  SDK/JDK build tools and includes a troubleshooting row for this error.

## [2.5.0] - 2026-11-08

### Added

- **50% Off Battleship Parts** (`ship_parts_half`): halves the three int64
  gold-cost arrays used by `worldboss_ship_part_gold_cost` (`0x75F790`,
  `0x75F880`, `0x75F950`), covering all seven Unknown Paradise battleship
  parts. CLI flag `--ship-parts-half`; matching GUI checkbox.
- **90% Off Core Crystal Upgrades** (`crystal_skill_90_off`): changes the
  `WORLDBOSS_SHIP_SKILL_LEVELUP` charge from 50 to 5 Kraken Scales
  (`0x84A2C0`) and rewrites the 29 client `crystalskillcost` rows from 50 to
  5, so the Unknown Paradise Core Processing Plant UI and the server agree.
  CLI flag `--crystal-skill-90-off`; matching GUI checkbox.

### Corrected

- The 2.4.0 note that coocoo sweep had no reward source was based on a
  malformed direct `DUNGEON_SWEEP` API request. Client-side **Subjugate** on
  Rock Coocoo's Garden 10 (3 sweeps) granted **12 level-440 coocoos** (4 per
  sweep), 16,500 gold and 480 event coins, and incremented `clear_cnt` 1 → 4.
  The 10x item multiplier still does not scale exp creatures; that is why
  `coocoo_level_x2` is the compensation.

### Validated

- **Coocoo Level x2 (runtime)**: Rock Coocoo's Garden 10 now drops four
  level-440 coocoos. The result screen and the save both confirm the four new
  monsters (`mon_idx` 1370–1373, `mon_level` 440). The earlier level-220 result
  came from a 2.3.0 APK that was still installed on the test device, not from
  the 2.4.0 patch.
- **Battleship part 50% (runtime)**: part 1 level 1→2 charged 2,500 gold
  instead of the original 5,000 (`lord_info.gold` 991,317,242 → 991,314,742).
- **Crystal skill 90% (runtime)**: skill 1 level 1→2 charged 5 Kraken Scales
  instead of 50 (`280001` count 590 → 585).
- Coocoo Level x2 was rebuilt in 2.5.0 after the 2.4.0 APK was not the build
  installed on the test device. The runtime drop validation is performed with
  this build.

## [2.4.0] - 2026-11-08

### Added

- **Coocoo Level x2** (`coocoo_level_x2`): doubles the stored coocoo level
  in all 20 Coocoo Garden stage rows (700010–700100 and 701010–701100). The
  final stages now drop level-440 coocoos instead of level-220, compensating
  for the fixed four-creature reward that the 10x item-drop multiplier cannot
  scale. CLI flag `--coocoo-level-x2`; matching GUI checkbox.

### Investigated / Known limitations

- **Dungeon Subjugation Ticket sweep** (corrected in 2.5.0): the server's
  `DungeonSweepStateAccess::finish` (`0x8D31C8`) only appends
  `clear_stage_info`, which led to the initial conclusion that the sweep had
  no reward source. Runtime testing in 2.5.0 shows the client **Subjugate**
  path does grant 4 coocoos per sweep (12 for 3 sweeps) plus gold and event
  coins. The 10x item multiplier does not scale exp creatures, so
  `coocoo_level_x2` is the correct compensation.
- **Guild Raid self-mercenary**: the existing NOP at `0x930100` removes the
  first self check in `guild_battle_hired_projection`, but the function then
  indexes the 1,000-row offline PVP opponent table using
  `lord_idx - 9900001` (`0x930118`/`0x930138`). The player's own lord ID
  (for example `993838`) is outside that range, so the projection returns
  empty and the self selection still fails. A code cave that builds the self
  projection from `infinity_local_hired_soldier_json` is required.

## [2.3.0] - 2026-11-08

### Added

- **Sacred Lands restoration** (`sacred_lands_restore`): the support-only
  slot-IV set was shipped with `_itemGrade: 1` in every client
  `setitemtable*.unity3d` bundle even though all of its equipment pieces are
  grade 4. The wrong grade hid it from the grade-4 rotation and ticket lists.
  The option restores grade 4 in all localized set tables and adds group `4028`
  to the ★4 set selection ticket lists (`10001`, `10004`). CLI flag
  `--sacred-lands-restore`; matching GUI checkbox.
- **Kraken Scale event reward**: the offline server's fixed three-event
  rotation never reaches the `10004` reward row. Event `10002`, which is the
  current event in every rotation window, had no usable item reward. It now
  grants the same Kraken Scale row as `10004`. Runtime validation through
  `WORLDBOSS_RESULT_EVENT` granted 290 Kraken Scales (item `280001` =
  `2621441`). This is part of `mode_drops_x10`.

### Fixed

- **Event Shop event-period limits**: the previous patch converted
  `limit_type:3` (Lifely) rows only. All 22 Event Shop rows using
  `limit_type:4` (Honor) are now converted to daily limits too, so every
  event-purchase restriction resets after 24 hours. The reference total is
  now 1,246 rows.
- **Build output naming**: generated APKs now default to
  `output/FWT-Reborn-Patched-<version>.apk` (for example
  `FWT-Reborn-Patched-2.3.0.apk`), and the patcher suite ZIP defaults to
  `output/FWT-Reborn-Patcher-Suite-<version>.zip`. Any custom output name
  without the current version gets it appended automatically. The standalone
  APK is no longer wrapped in a ZIP;
  `tools/create_distribution_zip.py --apk-only` only stages/copies the
  versioned APK.

### Validated

- Unknown Paradise was exercised with an advanced save through the embedded
  HTTP server (`WORLDBOSS_GET_MY_INFO`, `WORLDBOSS_START_GAME`,
  `WORLDBOSS_RESULT_GAME`). The daily reset date and the missing Kraken Scale
  source were confirmed from the live responses.

## [2.2.0] - 2026-11-08

### Added

- **10x Devil's Soul EXP Boost** (`devil_boost_x10`): using a Devil's Soul as
  an EXP-synthesis material now applies a 20x multiplier instead of the native
  2x. CLI flag `--devil-boost-x10`; matching GUI checkbox.

### Fixed

- **Battle of Honor Honor Coins**: the embedded server granted and displayed a
  hardcoded 6 coins per PvP win. The server result immediate is now 60, matching
  the 10x mode-drop option. The client preview asset remains patched as well.
- **Dimension Breakthrough genes**: the gene roll is now unconditional and the
  rolled gene count is multiplied by 10, instead of relying on a very low
  native drop chance.
- **Select All 4★/5★**: Multi Extraction now also accepts quality-4/5
  equipment. The runtime client hook includes a second `patch_words` call that
  routes those items into the Epic quality bucket, so Select All extracts
  high-grade gear whose quality was previously filtered out.

## [2.1.0] - 2026-11-08

### Added

- **Remove Equipment Drops** (`no_equip_drops`): removes equipment from every
  campaign/island stage drop pool and redistributes its weight proportionally
  to the other eligible drops in that stage (gold, items, monsters, manastone,
  genes and energy).
- **Recycling Capsules Give Hammers** (`recycle_hammer_rewards`): the
  alchemy/disassemble capsules now grant only hammer equipment. Normal
  capsules give gold/common or black hammers; the red/set capsule gives the
  green hammer. The server equipment table and the client `equipreward`
  table are patched together.
- **No Upgrade Failure Above +20** (`upgrade_no_fail_above_20`): sets the
  infinite-transcend success table for +21..+26 to 100%, so no insurance card
  is needed.
- **50% Hero Limit Break Cost** (`limit_break_cost_half`): halves both the gold
  and the material count (Unknown Fruit / Balance Jade) for all 45 limit-break
  rows. The legacy gold-only option remains available but is mutually exclusive.
- CLI flags: `--no-equip-drops`, `--recycle-hammers`, `--upgrade-no-fail` and
  `--limit-break-cost-half`; matching GUI checkboxes.

### Changed

- **Event Shop Discount is now 90%** (was 50%): every `shop_content:2` item is
  charged 10% of its original price, rounded up, with byte-length preservation.
- `--all` enables the new options and uses the combined limit-break cost patch.

## [2.0.1] - 2026-11-08

### Fixed

- Fresh installs no longer stop at the bootstrap error screen. When the internal
  `assets/fwt_resources_v1.zip` is patched, the build now rewrites the archive
  SHA-256, file count and uncompressed byte contract in `classes8.dex` so the
  bootstrap accepts the modified archive.
- The complete bootstrap UI is now English: title, status, progress format,
  failure details and the **Retry** button. The 47 hard-coded Korean strings are
  translated through a smali reassembly pass, which keeps the DEX string table
  lexicographically sorted and avoids the ART verification crash caused by the
  old in-place string rewrite.
- The English save-copy branch is now patched in smali (`saveCopy` returns the
  English string) instead of relying on fixed DEX offsets.
- LAN redirect DEX edits are applied before the smali rebuild, so both the
  offline and LAN builds keep the backup-prompt bypass.

### Changed

- Added a pinned apktool 2.10.0 dependency for the bootstrap smali pass. It is
  downloaded once to the user cache and verified against SHA-256; set
  `FWT_APKTOOL_JAR` to use a local copy.
- The internal resource archive is now rebuilt by replacing only the two
  patched datatables and copying every other ZIP record verbatim. This keeps the
  resource/contract hashes identical between Windows and Linux instead of
  depending on the host zlib implementation.
- `english_localization` now reports 55 changes: two SO gates, the `Qty`
  replacement, 51 bootstrap literals and the `saveCopy` branch.
- Project version bumped to `2.0.1`.

## [2.0.0] - 2026-11-08

### Added

- 10x Campaign Gold & Drops, 10x Campaign XP and 10x Expedition Rewards.
- 10x mode drops for Unknown Paradise, Battle of Honor, Dimension Breakthrough,
  Pit of Nephthys, Sky Library and Lost Island.
- 50% Campaign Shop discount across Honor, Ancient Coins, Guild Raid, Unknown
  Paradise and Friend Shop.
- Battle Arena team configuration save fix and empty-slot handling.
- Guild Raid self-mercenary selection.
- **Daily Event Shop Limits** option: converts event-limited rows
  (`limit_type=3`) to daily limits (`limit_type=1`) while keeping the original
  quantity, so items such as gem-upgrade materials can be purchased again after
  the daily reset.
- Patch version in the desktop window title/header and a new **About** menu
  with version, target build, repository, changelog and disclaimer information.
- This `CHANGELOG.md`.

### Changed

- Event Shop genes now use the catalog's `255` no-limit sentinel instead of
  `-1`, fixing the partial unlock where a large purchase could leave the item
  blocked afterwards.
- The campaign item trampoline now uses a stack flag and also multiplies item
  rewards for Pit of Nephthys and Lost Island stages.
- The patch version is now sourced from `core/version.py`; the CLI
  `--version` output uses the same value.
- Project version bumped to `2.0.0`.

### Fixed

- Pit of Nephthys subjugation now applies the item multiplier in addition to
  the base-gold multiplier.
- Event-limited shop items no longer stay locked for the whole event after the
  first purchase.
- English localization DEX patch replaced the unsafe bootstrap string rewrite
  with a bytecode-only `saveCopy` patch and checksum recalculation.
- **Runtime validation (2026-11-08):** Multi Extraction extracted 15 items
  including 4★/5★; Pit of Nephthys 10x Subjugate returned 400 items, 10,000 gold
  and 580 event coins; Dragon Fang showed `Today's Purchase Count 0/3`; a gene
  purchase dialog showed no limit.

### Known issues

- Stamina cashback companion: the embedded server treats
  `UPDATE_STAMINA_TIME` as read-only, so the companion cannot persist refunds.
  `--all` uses the server-side half-debit instead.
- Half-debit still requires full stamina in the client UI because the client
  validates the local stage cost table.

## [1.1.0] - 2026-11-07

### Added

- `stamina_potion_1000`: normal Stamina Potions restore 1000 points.
- `flask_3h`: 3-hour laboratory charge for the Mana Stone Compactor (the flag
  keeps its historical `flask_3h` name).
- Gold Cylinder six-hour timer guard.
- External `laboratorycount.unity3d` datatable patch tooling.
- Experimental host-side stamina cashback companion.
- 16 KB page-alignment and APK verification improvements.

### Changed

- `--all` uses the server-side 50% stamina half-debit again.
- Documentation and patch catalog updated with runtime findings.

### Fixed

- Laboratory datatable synchronization and patch idempotence.
- Stamina potion overcap display/state.

## [1.0.0] - 2026-11-06

### Added

- Initial cross-platform offline client patcher, GUI suite and reverse
  engineering documentation.
- Campaign, summon, event-shop, guild-raid, extraction and economy patches.
- APK repack, 16 KB alignment, signing, inspection and savegame backup tooling.

## Phase 8 — the DEV_DUMP endpoint

`--dev-endpoint` turns the instrumentation into a two-way channel: the entry cave spots a
`{"CMD":"DEV_DUMP"` request and the exit cave overwrites the returned `std::string` with
`{"ERROR":0,"DUMP":1}`. Verified on the MuMu by posting the command straight to the
embedded server over `nc` from the adb shell — the HTTP layer returned status 200 with the
injected body and a matching `Content-Length`.

The adb-shell route to `127.0.0.1:8010` works for **every** game command, which turns the
bench into a protocol console: no UI navigation needed to interrogate the embedded server.

Two defects found and fixed on the way: an inverted string-mode branch in the exit cave,
and a missing NUL after the injected payload that made the response log print the leftover
tail of the original body.

## 2.5.27 — option quality and rune quality

Two new features, both verified at the byte level in the generated APK and covered by
`tests/test_option_quality_patches.py` (212 tests, ruff and mypy clean, release verification
passing with 41 feature reports).

### Option-change potion: best attributes (`--option-max-attributes`)

`normalized_equipment_options_vector_json` (`0x9a08cc`) takes a quality bias in its last two
arguments: a `bool` and an `int` worth ``mastery_level * 30``. Every path that grants or
re-rolls gear passes the player's Lord mastery (skill code 20301, clamped to 15) — granting a
new item (`grant_equipment_json`), smelting (`apply_equipment_smelt_json`) and the state-access
change handler all pass `1` plus the computed bonus. The potion path
(`refresh_equipment_options_for_code_json`, `0xa16fb8`) is the only one that calls the roll with
`false` and `0`, so it never received the mastery bonus at all.

The patch restores the maximum bias at the potion site: `mov w3, #1` and `mov w4, #0x1c2`
(15 × 30).

### Rune options: maximum quality row (`--rune-option-quality`)

`rolled_rune_options_json` (`0xa2e65c`) reads the Lord mastery (skill code 20501), clamps it to
15 and indexes a 30-byte-per-row weight table at `0x719f10` with it, so the mastery level picks
how good the rolled rune attributes are. The patch replaces the mastery lookup with `mov x0,
#0xf`, keeping the existing clamp and always selecting the best row.

### Why these two and not the rest of the requested list

The Lord mastery is the hidden multiplier the user suspected: `mastery_level_in_state`
(`0xa16d24`) is called by 30 sites, including gear grants, smelts, rune rolls and rune enchant
success. The remaining requested features (hero Awake cost, soulgear/hero-mark upgrade success,
the SkyRuneSlot defence-only bug, subjugate drop list) live behind data tables or inside
`libil2cpp.so`, which is stripped; mapping them needs an IL2CPP dump, and there is no
`dotnet`/`mono` on this machine to run Il2CppDumper.
