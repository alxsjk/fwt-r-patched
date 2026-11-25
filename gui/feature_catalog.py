"""Stable identifiers and presentation groups for the GUI feature catalog.

IDs are permanent references shared with docs/FEATURE_CATALOG.md. Do not
renumber or reuse an ID, including when an option moves or is removed.
Allocate a new item number for new options.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Feature:
    number: str
    field: str
    variable: str | None
    cli: str
    name: str


@dataclass(frozen=True)
class FeatureGroup:
    number: str
    title: str
    features: tuple[Feature, ...]


FEATURE_GROUPS = (
    FeatureGroup("01", "Campaign, expeditions and modes", (
        Feature("01.01", "campaign_gold", "var_gold", "--campaign-gold", "Campaign gold and drops x10"),
        Feature("01.02", "campaign_xp", "var_xp", "--campaign-xp", "Campaign experience x10"),
        Feature("01.03", "no_equip_drops", "var_no_equip_drops", "--no-equip-drops", "Remove equipment drops"),
        Feature("01.04", "gene_priority", "var_gene", "--gene-priority", "Hero gene drop priority"),
        Feature("01.05", "expedition_bonus", "var_expedition", "--expeditions", "Expedition rewards x10"),
        Feature("01.06", "mode_drops_x10", "var_mode_drops_x10", "--mode-drops-x10", "Six game mode drops x10"),
        Feature("01.07", "event_coin_x10", "var_event_coin_x10", "--event-coin-x10", "Campaign event coins x10"),
        Feature("01.08", "devil_boost_x10", "var_devil_boost_x10", "--devil-boost-x10", "Devil's Soul EXP boost x10"),
        Feature("01.09", "coocoo_exp_x2", "var_coocoo_exp_x2", "--coocoo-exp-x2", "Coocoo EXP bonus x2"),
        Feature("01.10", "coocoo_level_x2", "var_coocoo_level_x2", "--coocoo-level-x2", "Coocoo drop level x2"),
    )),
    FeatureGroup("02", "Summons and shops", (
        Feature("02.01", "summon_rates", "var_summon", "--summon-rates", "Summon profile 70/20/10"),
        Feature("02.02", "summon_rates_50_30_20", "var_summon_50_30_20", "--summon-50-30-20", "Summon profile 50/30/20"),
        Feature("02.03", "event_discount", "var_event_discount", "--event-discount", "Event shop 90% discount"),
        Feature("02.04", "event_gene_unlimited", "var_event_gene_unlimited", "--event-gene-unlimited", "Unlimited event shop genes"),
        Feature("02.05", "event_limits_daily", "var_event_limits_daily", "--event-limits-daily", "Daily event shop limits"),
        Feature("02.06", "campaign_shop_discount", "var_campaign_shop_discount", "--campaign-shop-discount", "Campaign shop 90% discount"),
        Feature("02.07", "mythical_stone_shop", "var_mythical_stone_shop", "--mythical-stone-shop", "Mythical Stone in Event Shop"),
        Feature("02.08", "costume_packages_all", "var_costume_packages_all", "--costume-packages-all", "Complete Costume Packages"),
        Feature("02.09", "hero_shop_offers", "var_hero_shop_offers", "--hero-shop-offers", "Evan and Alex Shop Offers"),
        Feature("02.10", "surprise_transcendence_package", "var_surprise_transcendence_package", "--surprise-transcendence-package", "Surprise Transcendence Package 2"),
    )),
    FeatureGroup("03", "Equipment and soulgear", (
        Feature("03.01", "recycle_six_star", "var_recycle_six_star", "--recycle-six-star", "Recycling grants 6-star equipment"),
        Feature("03.02", "option_max_attributes", "var_option_max_attributes", "--option-max-attributes", "Max quality on every option roll"),
        Feature("03.03", "equipment_lock_fix", "var_equipment_lock_fix", "--equipment-lock-fix", "Preserve locked equipment options"),
        Feature("03.04", "equipment_single_mod_stone", "var_equipment_single_mod_stone", "--equipment-single-mod-stone", "One Modification Stone"),
        Feature("03.05", "equipment_percent_options", "var_equipment_percent_options", "--equipment-percent-options", "Percentage-only equipment options"),
        Feature("03.06", "equipment_upgrade_10_guarantee", "var_equipment_upgrade_10_guarantee", "--equipment-upgrade-10-guarantee", "Guaranteed +9 to +10 upgrade"),
        Feature("03.07", "upgrade_no_fail_above_20", "var_upgrade_no_fail_above_20", "--upgrade-no-fail", "Guaranteed +21 to +26 upgrades"),
        Feature("03.08", "single_black_hammer", "var_single_black_hammer", "--single-black-hammer", "One Black Hammer per attempt"),
        Feature("03.09", "soulgear_enchant_always", "var_soulgear_enchant_always", "--soulgear-enchant-always", "Guaranteed soulgear enchant"),
        Feature("03.10", "sacred_lands_restore", "var_sacred_lands_restore", "--sacred-lands-restore", "Restore Sacred Lands set"),
        Feature("03.11", "equipment_tier_upgrades", "var_equipment_tier_upgrades", "--equipment-tier-upgrades", "One hammer per equipment tier"),
    )),
    FeatureGroup("04", "Runes", (
        Feature("04.01", "rune_box_random_type", "var_rune_box_random_type", "--rune-box-random-type", "Rune box random type"),
        Feature("04.02", "rune_box_random_roll", "var_rune_box_random_roll", "--rune-box-random-roll", "Rune box random slot and type"),
        Feature("04.03", "rune_quality_factor", "var_rune_quality_x10", "--rune-quality-factor", "Rune attribute mastery bias and percentage-only rolls"),
        Feature("04.04", "rune_option_quality", "var_rune_option_quality", "--rune-option-quality", "Rune maximum mastery row"),
        Feature("04.05", "rune_upgrade_discount", "var_rune_upgrade_discount", "--rune-upgrade", "Rune upgrades +12..+15 always succeed and cost a tenth"),
    )),
    FeatureGroup("05", "Gems", (
        Feature("05.01", "gem_mining_x10", "var_gem_mining_x10", "--gem-mining-x10", "Gem mining x10"),
        Feature("05.02", "gem_mining_types", "var_gem_mining_types", "--gem-mining-types", "Gem mining type filter"),
        Feature("05.03", "gem_level6", "var_gem_level6", "--gem-level6", "Level 6 gems"),
        Feature("05.04", "gem_upgrade_gold_half", "var_gem_upgrade_gold_half", "--gem-upgrade-gold-half", "Gem upgrade gold cost halved"),
        Feature("05.05", "single_gem_fang", "var_single_gem_fang", "--single-gem-fang", "One Dragon Fang opens all 3 gem slots"),
    )),
    FeatureGroup("06", "Resources and upgrade costs", (
        Feature("06.01", "energy_flask_x10", "var_energy_flask_x10", "--energy-flask-x10", "Energy Flask x10 stamina"),
        Feature("06.02", "gold_cylinder_x10", "var_gold_cylinder_x10", "--gold-cylinder-x10", "Gold Cylinder x10 gold"),
        Feature("06.03", "mana_cylinder_x10", "var_mana_cylinder_x10", "--mana-cylinder-x10", "Mana Stone Compactor x10 mana"),
        Feature("06.04", "stamina_cost_half", "var_stamina_cost_half", "--stamina-cost-half", "Dungeon stamina cost halved"),
        Feature("06.05", "stamina_potion_1000", "var_stamina_potion_1000", "--stamina-potion-1000", "Stamina potion restores 1000"),
        Feature("06.06", "limit_break_cost_tenth", "var_limit_break_cost_tenth", "--limit-break-cost-tenth", "Hero limit break 90% discount"),
        Feature("06.07", "ship_parts_90_off", "var_ship_parts_90_off", "--ship-parts-90-off", "Battleship parts 90% discount"),
        Feature("06.08", "crystal_skill_90_off", "var_crystal_skill_90_off", "--crystal-skill-90-off", "Core crystal skills 90% discount"),
        Feature("06.09", "limit_break_cost_fixed", "var_limit_break_cost_fixed", "--limit-break-cost-fixed", "Flat hero limit break cost (1M gold + 100 Balance Jade)"),
        Feature("06.10", "worldboss_full_ship_repair", "var_worldboss_full_ship_repair", "--worldboss-full-ship-repair", "Unknown Paradise Full Ship Repair"),
    )),
    FeatureGroup("07", "Battle Arena and Guild Raid", (
        Feature("07.01", "battle_arena_fix", "var_battle_arena_fix", "--battle-arena-fix", "Battle Arena team save fix"),
        Feature("07.02", "battle_arena_save_fix", "var_battle_arena_save_fix", "--battle-arena-save-fix", "Battle Arena Save button fix"),
        Feature("07.03", "guild_raid_mercenary", "var_guild_raid_mercenary", "--guild-raid-mercenary", "Guild Raid own mercenary"),
        Feature("07.04", "guild_raid_reward_x10", "var_guild_raid_reward_x10", "--guild-raid-reward-x10", "Guild Raid rewards x10"),
        Feature("07.05", "guild_raid_score_fix", "var_guild_raid_score_fix", "--guild-raid-score-fix", "Guild Raid 64-bit scores"),
        Feature(
            "07.06",
            "guild_raid_fire_support",
            "var_guild_raid_fire_support",
            "--guild-raid-fire-support",
            "Guild Raid Fire Support 100% HP and minion-aware auto-cast",
        ),
        Feature(
            "07.07",
            "guild_raid_skills_max",
            "var_guild_raid_skills_max",
            "--guild-raid-skills-max",
            "Guild Raid skills maxed (1M Shelling, 100% DR/HP/MP, 20 dispels)",
        ),
        Feature(
            "07.08",
            "guild_raid_boss_no_counter",
            "var_guild_raid_boss_no_counter",
            "--guild-raid-boss-no-counter",
            "Guild Raid boss 0% counterattack rate",
        ),
        Feature(
            "07.09",
            "guild_raid_protection_persist",
            "var_guild_raid_protection_persist",
            "--guild-raid-protection-persist",
            "Guild Raid Absolute Protection persists for all hits",
        ),
        Feature(
            "07.10",
            "guild_raid_skill_turn_gate",
            "var_guild_raid_skill_turn_gate",
            "--guild-raid-skill-turn-gate",
            "Guild Raid lord skills auto-cast at most once per turn (Fire Support untouched)",
        ),
    )),
    FeatureGroup("08", "Language, network and build", (
        Feature("08.01", "english_localization", "var_english", "--english", "English localization"),
        Feature("08.02", "align_16k", "var_align_16k", "--no-16k", "16 KB alignment"),
        Feature("08.03", "no_win_box", None, "always on", "Hide phantom Coocoo boxes"),
        Feature("08.04", "lan_redirect", None, "--lan", "LAN server redirect"),
        Feature("08.05", "allow_unknown", None, "--force", "Allow non-reference APK"),
        Feature("08.06", "hero_exp_cap", None, "always on", "Hero EXP cap and Limit Break floor"),
        Feature("08.07", "convert_hex_guard", None, "always on", "Non-hex inventory sync guard (KB-001)"),
        Feature("08.08", "dungeon_recom_info", None, "always on", "Mercenary auto-select recommendations"),
    )),
    FeatureGroup("12", "Original hero modifications", (
        Feature("12.01", "alex_awakening", "var_alex_awakening", "--alex-awakening", "Alex Awakening: Destiny Lance"),
        Feature("12.02", "alex_rebalance", "var_alex_rebalance", "--alex-rebalance", "Alex Skill, Passive & Awake Rebalance (Skill 1 = Skill 2 geometry; Skill 2 reduces Defense)"),
        Feature("12.03", "alex_heros_mark", "var_alex_heros_mark", "--alex-heros-mark", "Alex's Hero's Mark — The Unbroken Lance"),
    )),
    FeatureGroup("13", "Heroes and traits", (
        Feature("13.01", "trait_max_quality", "var_trait_max_quality", "--trait-max-quality", "Traits: Max quality on every roll"),
        Feature("13.02", "trait_allow_duplicates", "var_trait_allow_duplicates", "--trait-allow-duplicates", "Allow duplicate hero traits across slots"),
        Feature("13.03", "limit_break_step_10", "var_limit_break_step_10", "--limit-break-step-10", "Limit Break opens +10 levels per step (to Lv 120)"),
        Feature("13.04", "trait_multi_unique", "var_trait_multi_unique", "--trait-multi-unique", "Traits: Multi-roll batch never repeats attributes"),
        Feature("13.05", "trait_immunity_weight_x2", "var_trait_immunity_weight_x2", "--trait-immunity-weight-x2", "Traits: Double immunity weights (Slots 3-5)"),
    )),
    FeatureGroup("14", "Auto-battle AI", (
        Feature("14.01", "merlin_auto_support", "var_merlin_auto_support", "--merlin-auto-support", "Merlin Slot-1 Auto Mode: Awake, then Magic infusion (strongest Awakening first), before bonus or item cells"),
    )),
)


DEV_GROUPS = (
    FeatureGroup("09", "Development: telemetry and controls", (
        Feature("09.01", "dev.enabled", "var_dev_enabled", "--dev", "Enable development build"),
        Feature("09.02", "dev.log_dispatch", "var_dev_log", "--dev-log", "Dispatch request logging"),
        Feature("09.03", "dev.hit_counters", "var_dev_counters", "--dev-counters", "Execution counters"),
        Feature("09.04", "dev.handler_timing", "var_dev_timing", "--dev-timing", "Handler timing"),
        Feature("09.05", "dev.log_body_limit", "var_dev_log_limit", "--dev-log-limit", "Log body size limit"),
        Feature("09.06", "dev.log_commands", "var_dev_log_commands", "--dev-log-commands", "Command filter (offline only)"),
    )),
    FeatureGroup("10", "Development: tools", (
        Feature("10.01", "dev.debuggable", "var_dev_debuggable", "--dev-debuggable", "Debuggable manifest"),
        Feature("10.02", "dev.keep_version", "var_dev_keep_version", "--dev-keep-version", "Keep manifest version"),
        Feature("10.03", "dev.build_marker", "var_dev_marker", "--dev-marker", "Build marker"),
        Feature("10.04", "dev.log_responses", "var_dev_log_response", "--dev-log-response", "Response body logging"),
        Feature("10.05", "dev.dev_endpoint", "var_dev_endpoint", "--dev-endpoint", "DEV_DUMP endpoint"),
    )),
    FeatureGroup("11", "Development: experimental", (
        Feature("11.01", "dev.state_snapshots", "var_dev_snapshots", "--dev-snapshots", "State snapshots (pending)"),
        Feature("11.02", "dev.lab_traps", "var_lab_traps", "--lab-traps", "Laboratory traps (pending)"),
    )),
)


def feature_by_field(field: str) -> Feature:
    """Return the unique feature with this patch option field."""
    return next(feature for group in (*FEATURE_GROUPS, *DEV_GROUPS)
                for feature in group.features if feature.field == field)
