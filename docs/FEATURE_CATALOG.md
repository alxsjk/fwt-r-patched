# Grouped Feature Catalog

This is the canonical index of GUI feature numbers for FWT Reborn Patch 2.5.61. The same IDs appear in the graphical interface. For code locations, byte sequences and validation history, see [PATCH_SPEC.md](PATCH_SPEC.md).

IDs are stable references, not positions: never renumber or reuse an ID. If a feature moves to another group, keep its existing ID; its prefix identifies the group in which it was first assigned. Add new items with a new number in the relevant group and update `gui/feature_catalog.py` and this catalog together. The parity tests verify the mapping.

`--all` enables the gameplay and localization options in groups 01–08 and 12–14, uses the 50/30/20 summon profile and rune factor 10, and keeps 16 KB alignment. LAN is selected separately. The 70/20/10 profile can replace the default by combining `--all --summon-rates`. For hero limit breaks, `--all` selects the flat cost (`06.09`) unless `--limit-break-cost-tenth` (`06.06`) is passed.

## 01 — Campaign, expeditions and modes

| ID | Feature | CLI | PatchOptions field | GUI variable | `--all` |
|---|---|---|---|---|---|
| 01.01 | Campaign gold and drops x10 | `--campaign-gold` | `campaign_gold` | `var_gold` | Yes |
| 01.02 | Campaign experience x10 | `--campaign-xp` | `campaign_xp` | `var_xp` | Yes |
| 01.03 | Remove equipment drops | `--no-equip-drops` | `no_equip_drops` | `var_no_equip_drops` | Yes |
| 01.04 | Hero gene drop priority | `--gene-priority` | `gene_priority` | `var_gene` | Yes |
| 01.05 | Expedition rewards x10 | `--expeditions` | `expedition_bonus` | `var_expedition` | Yes |
| 01.06 | Six game mode drops x10 | `--mode-drops-x10` | `mode_drops_x10` | `var_mode_drops_x10` | Yes |
| 01.07 | Campaign event coins x10 | `--event-coin-x10` | `event_coin_x10` | `var_event_coin_x10` | Yes |
| 01.08 | Devil's Soul EXP boost x10 | `--devil-boost-x10` | `devil_boost_x10` | `var_devil_boost_x10` | Yes |
| 01.09 | Coocoo EXP bonus x2 | `--coocoo-exp-x2` | `coocoo_exp_x2` | `var_coocoo_exp_x2` | Yes |
| 01.10 | Coocoo drop level x2 | `--coocoo-level-x2` | `coocoo_level_x2` | `var_coocoo_level_x2` | Yes |

## 02 — Summons and shops

| ID | Feature | CLI | PatchOptions field | GUI variable | `--all` |
|---|---|---|---|---|---|
| 02.01 | Summon profile 70/20/10 | `--summon-rates` | `summon_rates` | `var_summon` | Alternative |
| 02.02 | Summon profile 50/30/20 | `--summon-50-30-20` | `summon_rates_50_30_20` | `var_summon_50_30_20` | Yes |
| 02.03 | Event shop 90% discount | `--event-discount` | `event_discount` | `var_event_discount` | Yes |
| 02.04 | Unlimited event shop genes | `--event-gene-unlimited` | `event_gene_unlimited` | `var_event_gene_unlimited` | Yes |
| 02.05 | Daily event shop limits | `--event-limits-daily` | `event_limits_daily` | `var_event_limits_daily` | Yes |
| 02.06 | Campaign shop 90% discount (including valid category-6 coin prices) | `--campaign-shop-discount` | `campaign_shop_discount` | `var_campaign_shop_discount` | Yes |
| 02.07 | Mythical Stone in Event Shop | `--mythical-stone-shop` | `mythical_stone_shop` | `var_mythical_stone_shop` | Yes ([KB-001](KNOWN_BUGS.md), resolved in 2.5.55) |
| 02.08 | Complete Costume Packages: one copy of each eligible owned costume; each package up to 10 times daily | `--costume-packages-all` | `costume_packages_all` | `var_costume_packages_all` | Yes |
| 02.09 | Evan and Alex Shop Offers: unlimited genes (5 event coins / 1 medal); Honor Shop 100 Diamonds | `--hero-shop-offers` | `hero_shop_offers` | `var_hero_shop_offers` | Yes |
| 02.10 | Surprise Transcendence Package 2 (10 Ultimate and 10 Universal tickets for 500 diamonds) | `--surprise-transcendence-package` | `surprise_transcendence_package` | `var_surprise_transcendence_package` | Yes |

## 03 — Equipment and soulgear

| ID | Feature | CLI | PatchOptions field | GUI variable | `--all` |
|---|---|---|---|---|---|
| 03.01 | Recycling grants 6-star equipment | `--recycle-six-star` | `recycle_six_star` | `var_recycle_six_star` | Yes |
| 03.02 | Max quality on every option roll (pink, including when combined with 03.05) | `--option-max-attributes` | `option_max_attributes` | `var_option_max_attributes` | Yes |
| 03.03 | Preserve locked equipment options | `--equipment-lock-fix` | `equipment_lock_fix` | `var_equipment_lock_fix` | Yes |
| 03.04 | One Modification Stone | `--equipment-single-mod-stone` | `equipment_single_mod_stone` | `var_equipment_single_mod_stone` | Yes |
| 03.05 | Percentage-only equipment options (excludes direct and scaled flat values) | `--equipment-percent-options` | `equipment_percent_options` | `var_equipment_percent_options` | Yes |
| 03.06 | Guaranteed +9 to +10 upgrade | `--equipment-upgrade-10-guarantee` | `equipment_upgrade_10_guarantee` | `var_equipment_upgrade_10_guarantee` | Yes |
| 03.07 | Guaranteed +21 to +26 upgrades | `--upgrade-no-fail` | `upgrade_no_fail_above_20` | `var_upgrade_no_fail_above_20` | Yes |
| 03.08 | One Black Hammer per attempt | `--single-black-hammer` | `single_black_hammer` | `var_single_black_hammer` | Yes |
| 03.09 | Guaranteed soulgear enchant | `--soulgear-enchant-always` | `soulgear_enchant_always` | `var_soulgear_enchant_always` | Yes |
| 03.10 | Restore Sacred Lands set | `--sacred-lands-restore` | `sacred_lands_restore` | `var_sacred_lands_restore` | Yes |
| 03.11 | One hammer per equipment tier | `--equipment-tier-upgrades` | `equipment_tier_upgrades` | `var_equipment_tier_upgrades` | Yes |

## 04 — Runes

| ID | Feature | CLI | PatchOptions field | GUI variable | `--all` |
|---|---|---|---|---|---|
| 04.01 | Rune box random type | `--rune-box-random-type` | `rune_box_random_type` | `var_rune_box_random_type` | Yes |
| 04.02 | Rune box random slot and type | `--rune-box-random-roll` | `rune_box_random_roll` | `var_rune_box_random_roll` | Yes |
| 04.03 | Rune attribute mastery bias and percentage-only rolls | `--rune-quality-factor N` | `rune_quality_factor` | `var_rune_quality_x10` | Yes, N=10 |
| 04.04 | Rune maximum mastery row and top-quality rolls | `--rune-option-quality` | `rune_option_quality` | `var_rune_option_quality` | Yes |
| 04.05 | Rune upgrades +12..+15 always succeed and cost a tenth | `--rune-upgrade` | `rune_upgrade_discount` | `var_rune_upgrade_discount` | Yes |

## 05 — Gems

| ID | Feature | CLI | PatchOptions field | GUI variable | `--all` |
|---|---|---|---|---|---|
| 05.01 | Gem mining x10 | `--gem-mining-x10` | `gem_mining_x10` | `var_gem_mining_x10` | Yes |
| 05.02 | Gem mining type filter | `--gem-mining-types` | `gem_mining_types` | `var_gem_mining_types` | Yes |
| 05.03 | Level 6 gems | `--gem-level6` | `gem_level6` | `var_gem_level6` | Yes |
| 05.04 | Gem upgrade gold cost halved | `--gem-upgrade-gold-half` | `gem_upgrade_gold_half` | `var_gem_upgrade_gold_half` | Yes |
| 05.05 | One Dragon Fang opens all 3 gem slots | `--single-gem-fang` | `single_gem_fang` | `var_single_gem_fang` | Yes |

## 06 — Resources and upgrade costs

| ID | Feature | CLI | PatchOptions field | GUI variable | `--all` |
|---|---|---|---|---|---|
| 06.01 | Energy Flask x10 stamina | `--energy-flask-x10` | `energy_flask_x10` | `var_energy_flask_x10` | Yes |
| 06.02 | Gold Cylinder x10 gold | `--gold-cylinder-x10` | `gold_cylinder_x10` | `var_gold_cylinder_x10` | Yes |
| 06.03 | Mana Stone Compactor x10 mana | `--mana-cylinder-x10` | `mana_cylinder_x10` | `var_mana_cylinder_x10` | Yes |
| 06.04 | Dungeon stamina cost halved | `--stamina-cost-half` | `stamina_cost_half` | `var_stamina_cost_half` | Yes |
| 06.05 | Stamina potion restores 1000 | `--stamina-potion-1000` | `stamina_potion_1000` | `var_stamina_potion_1000` | Yes |
| 06.06 | Hero limit break 90% discount | `--limit-break-cost-tenth` | `limit_break_cost_tenth` | `var_limit_break_cost_tenth` | No (superseded by 06.09) |
| 06.07 | Battleship parts 90% discount | `--ship-parts-90-off` | `ship_parts_90_off` | `var_ship_parts_90_off` | Yes |
| 06.08 | Core crystal skills 90% discount | `--crystal-skill-90-off` | `crystal_skill_90_off` | `var_crystal_skill_90_off` | Yes |
| 06.09 | Flat hero limit break cost (1M gold + 100 Balance Jade) | `--limit-break-cost-fixed` | `limit_break_cost_fixed` | `var_limit_break_cost_fixed` | Yes |
| 06.10 | Unknown Paradise Full Ship Repair | `--worldboss-full-ship-repair` | `worldboss_full_ship_repair` | `var_worldboss_full_ship_repair` | Yes |

## 07 — Battle Arena and Guild Raid

| ID | Feature | CLI | PatchOptions field | GUI variable | `--all` |
|---|---|---|---|---|---|
| 07.01 | Battle Arena team save fix | `--battle-arena-fix` | `battle_arena_fix` | `var_battle_arena_fix` | Yes |
| 07.02 | Battle Arena Save button fix | `--battle-arena-save-fix` | `battle_arena_save_fix` | `var_battle_arena_save_fix` | Yes |
| 07.03 | Guild Raid own mercenary | `--guild-raid-mercenary` | `guild_raid_mercenary` | `var_guild_raid_mercenary` | Yes |
| 07.04 | Guild Raid rewards x10 | `--guild-raid-reward-x10` | `guild_raid_reward_x10` | `var_guild_raid_reward_x10` | Yes |
| 07.05 | Guild Raid 64-bit scores | `--guild-raid-score-fix` | `guild_raid_score_fix` | `var_guild_raid_score_fix` | Yes |
| 07.06 | Guild Raid Fire Support 100% HP and minion-aware auto-cast | `--guild-raid-fire-support` | `guild_raid_fire_support` | `var_guild_raid_fire_support` | Yes |
| 07.07 | Guild Raid skills maxed (1M Shelling, 100% DR/HP/MP, 20 dispels) | `--guild-raid-skills-max` | `guild_raid_skills_max` | `var_guild_raid_skills_max` | Yes |
| 07.08 | Guild Raid boss 0% counterattack rate | `--guild-raid-boss-no-counter` | `guild_raid_boss_no_counter` | `var_guild_raid_boss_no_counter` | Yes |
| 07.09 | Guild Raid Absolute Protection persists for all hits | `--guild-raid-protection-persist` | `guild_raid_protection_persist` | `var_guild_raid_protection_persist` | Yes |
| 07.10 | Guild Raid lord skills auto-cast at most once per turn (Fire Support untouched) | `--guild-raid-skill-turn-gate` | `guild_raid_skill_turn_gate` | `var_guild_raid_skill_turn_gate` | Yes |

07.03 uses the configured weekday hero; if absent or invalid, it keeps the
selected guild mercenary. A hero without a costume remains valid. Socketed gem
bonuses are still under investigation and are not yet guaranteed.

## 08 — Language, network and build

| ID | Feature | CLI | PatchOptions field | GUI variable | `--all` |
|---|---|---|---|---|---|
| 08.01 | English localization (UI, Summon, Shop, mini-shops, server strings & client tables) | `--english` | `english_localization` | `var_english` | Yes |
| 08.02 | 16 KB alignment | `--no-16k` disables | `align_16k` | `var_align_16k` | Default on |
| 08.03 | Hide phantom Coocoo boxes and disable bonus boxes in hero-gene Subjugation | Always on | Built-in fix | None | Always |
| 08.04 | LAN server redirect | `--lan` | `lan_redirect` | `net_mode_var` | No |
| 08.05 | Allow non-reference APK | `--force` | `allow_unknown` | `var_force` | No |
| 08.06 | Hero EXP cap and Limit Break floor | Always on | Built-in fix | None | Always |
| 08.07 | Non-hex inventory sync guard (KB-001) | Always on | Built-in fix | None | Always |
| 08.08 | Mercenary auto-select recommendations (`DUNGEON_RECOM_INFO`) | Always on | Built-in fix | None | Always |

## 12 — Original hero modifications

See the [Awakening guide](HERO_AWAKENING_GUIDE.md), [Skill rebalance guide](SKILL_REBALANCE_GUIDE.md), and [Hero's Mark guide](HEROS_MARK_GUIDE.md) for details.

| ID | Feature | CLI | PatchOptions field | GUI variable | `--all` |
|---|---|---|---|---|---|
| 12.01 | Alex Awakening: Destiny Lance | `--alex-awakening` | `alex_awakening` | `var_alex_awakening` | Yes |
| 12.02 | Alex Skill, Passive & Awake Rebalance (Skill 1 = Skill 2 geometry; Skill 2 reduces Defense) | `--alex-rebalance` | `alex_rebalance` | `var_alex_rebalance` | Yes |
| 12.03 | Alex's Hero's Mark — The Unbroken Lance | `--alex-heros-mark` | `alex_heros_mark` | `var_alex_heros_mark` | Yes |

## 13 — Heroes and traits

| ID | Feature | CLI | PatchOptions field | GUI variable | `--all` |
|---|---|---|---|---|---|
| 13.01 | Traits: Max quality on every roll (always pink / grade 5) | `--trait-max-quality` | `trait_max_quality` | `var_trait_max_quality` | Yes |
| 13.02 | Allow duplicate hero traits across slots | `--trait-allow-duplicates` | `trait_allow_duplicates` | `var_trait_allow_duplicates` | Yes |
| 13.03 | Limit Break opens +10 levels per step (to Lv 120) | `--limit-break-step-10` | `limit_break_step_10` | `var_limit_break_step_10` | Yes |
| 13.04 | Traits: Multi-roll batch never repeats attributes in one rolled list | `--trait-multi-unique` | `trait_multi_unique` | `var_trait_multi_unique` | Yes |
| 13.05 | Traits: Double immunity weights (Slots 3-5) (20,000 vs 10,000 normal) | `--trait-immunity-weight-x2` | `trait_immunity_weight_x2` | `var_trait_immunity_weight_x2` | Yes |

## 14 — Auto-battle AI

| ID | Feature | CLI | PatchOptions field | GUI variable | `--all` |
|---|---|---|---|---|---|
| 14.01 | Merlin Slot-1 Auto Mode: Awake, then Magic infusion (strongest Awakening first), before bonus or item cells | `--merlin-auto-support` | `merlin_auto_support` | `var_merlin_auto_support` | Yes |

*Note: Historical sub-IDs `14.02` (prioritize skills before bonus/item cells) and `14.03` (strongest-Awakening damage tie-break) are bundled into `14.01` (`--merlin-auto-support`) and reserved against reuse.*

## Development options

Groups 09–11 are for development builds and are not enabled by `--all`. The dev master switch is required for instrumentation. See [DEV_BUILD.md](DEV_BUILD.md) for details and limitations.

### 09 — Development: telemetry and controls

| ID | Feature | CLI | DevOptions field | GUI variable | Status |
|---|---|---|---|---|---|
| 09.01 | Enable development build | `--dev` | `dev.enabled` | `var_dev_enabled` | Available |
| 09.02 | Dispatch request logging | `--dev-log` | `dev.log_dispatch` | `var_dev_log` | Available |
| 09.03 | Execution counters | `--dev-counters` | `dev.hit_counters` | `var_dev_counters` | Available |
| 09.04 | Handler timing | `--dev-timing` | `dev.handler_timing` | `var_dev_timing` | Available |
| 09.05 | Log body size limit | `--dev-log-limit BYTES` | `dev.log_body_limit` | `var_dev_log_limit` | Available |
| 09.06 | Command filter (offline only) | `--dev-log-commands CSV` | `dev.log_commands` | `var_dev_log_commands` | Offline filtering only |

### 10 — Development: tools

| ID | Feature | CLI | DevOptions field | GUI variable | Status |
|---|---|---|---|---|---|
| 10.01 | Debuggable manifest | `--dev-debuggable` | `dev.debuggable` | `var_dev_debuggable` | Available |
| 10.02 | Keep manifest version | `--dev-keep-version` | `dev.keep_version` | `var_dev_keep_version` | Available |
| 10.03 | Build marker | `--dev-marker` | `dev.build_marker` | `var_dev_marker` | Available |
| 10.04 | Response body logging | `--dev-log-response` | `dev.log_responses` | `var_dev_log_response` | Available |
| 10.05 | DEV_DUMP endpoint | `--dev-endpoint` | `dev.dev_endpoint` | `var_dev_endpoint` | Available |

### 11 — Development: experimental

| ID | Feature | CLI | DevOptions field | GUI variable | Status |
|---|---|---|---|---|---|
| 11.01 | State snapshots (pending) | `--dev-snapshots` | `dev.state_snapshots` | `var_dev_snapshots` | Pending |
| 11.02 | Laboratory traps (pending) | `--lab-traps` | `dev.lab_traps` | `var_lab_traps` | Pending |

## Selection notes

- **02.01 / 02.02:** summon profiles are mutually exclusive. The GUI automatically clears the other profile.
- **04.03:** the GUI switch selects factor 10; the CLI accepts a nonnegative factor. The bonus is `min(10000, 450 × N)`, not a guarantee of the highest attribute. The switch also drops the fixed-value attributes from both the server and the client rune-option tables.
- **04.05:** guarantees +12..+15 rune upgrades and cuts their gold cost to one tenth (`--rune-upgrade`, `rune_upgrade_discount`, enabled by `--all`).
- **06.04:** only the server debit is halved; the client can still display or require the full stamina cost.
- **08.02:** alignment is enabled by default and `--no-16k` disables it; release distribution requires 16 KB alignment.
- **08.03:** the Coocoo box correction is unconditional and has no selectable flag.
- **08.04:** offline mode is the default; LAN requires an explicit IP and optional port.
- **08.05:** the advanced non-reference input override is in the APK selection card and is off by default.
- **08.08:** the pre-battle mercenary auto-select fix is unconditional and has no selectable flag; the client's "auto select" finally receives a `recom_list` (served from the friends data) instead of the stock empty ack.
- Development instrumentation is separate from release features; groups 09–11 and [DEV_BUILD.md](DEV_BUILD.md) distinguish implemented and pending options.
- Removed gameplay features are historical only; they are not selectable and have no current IDs. Pending development controls remain labeled above.
