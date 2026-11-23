"""Guard: every patch option must be reachable and wired cleanly in the GUI.

The project rule is that any feature implemented in the patch engine has to be
switchable from the interface without silently producing conflicting defaults
or dead toggles.
"""

from __future__ import annotations

import dataclasses
import re
import tkinter as tk
import tkinter.font as tkfont
from collections.abc import Callable
from pathlib import Path

import pytest

from core.core_patches import DevOptions, PatchOptions, validate_patch_options
from fwt_patcher import build_parser
from gui.feature_catalog import DEV_GROUPS, FEATURE_GROUPS
from gui.main_window import MainWindow

GUI = Path(__file__).resolve().parent.parent / "gui" / "main_window.py"
CATALOG_DOC = GUI.parent.parent / "docs" / "FEATURE_CATALOG.md"

# Options that are build plumbing rather than features (paths, toggles handled elsewhere).
PIPELINE_FIELDS = {
    "input_apk",
    "output_apk",
}


class _FakeBoolVar:
    """Headless test double replicating ``tkinter.BooleanVar`` write traces."""

    def __init__(self, *, value: bool = False) -> None:
        self._value = bool(value)
        self._traces: list[Callable[[str, str, str], object]] = []

    def get(self) -> bool:
        return self._value

    def set(self, value: bool) -> None:
        self._value = bool(value)
        for callback in list(self._traces):
            callback("", "", "write")

    def trace_add(
        self, mode: str, callback: Callable[[str, str, str], object]
    ) -> str:
        assert mode == "write"
        self._traces.append(callback)
        return f"trace_{len(self._traces)}"


def _build_headless_window(monkeypatch: pytest.MonkeyPatch) -> MainWindow:
    monkeypatch.setattr("gui.main_window.tk.BooleanVar", _FakeBoolVar)
    window = MainWindow.__new__(MainWindow)
    window._init_option_vars()
    window._bind_option_exclusions()
    return window


def test_every_patch_option_is_exposed_in_the_gui() -> None:
    source = GUI.read_text(encoding="utf-8")
    fields = [
        field.name
        for field in dataclasses.fields(PatchOptions)
        if field.name not in PIPELINE_FIELDS
    ]
    missing = [name for name in fields if name not in source]
    assert not missing, (
        "these PatchOptions have no GUI control: " + ", ".join(sorted(missing))
    )


def test_grouped_catalog_covers_options_flags_and_documentation() -> None:
    groups = (*FEATURE_GROUPS, *DEV_GROUPS)
    features = [feature for group in groups for feature in group.features]
    ids = [feature.number for feature in features]
    fields = [feature.field for feature in features]
    variables = [feature.variable for feature in features if feature.variable is not None]
    assert len(ids) == len(set(ids))
    assert len(fields) == len(set(fields))
    assert len(variables) == len(set(variables))
    assert len({group.number for group in groups}) == len(groups)

    infrastructure = {"server_ip", "server_port", "dev"}
    patch_fields = {field.name for field in dataclasses.fields(PatchOptions)} - infrastructure
    assert {field for field in fields if not field.startswith("dev.")} == patch_fields | {
        "no_win_box",
        "hero_exp_cap",
        "convert_hex_guard",
        "dungeon_recom_info",
    }
    assert {field.removeprefix("dev.") for field in fields if field.startswith("dev.")} == {
        field.name for field in dataclasses.fields(DevOptions)
    }
    parser_flags = {option for action in build_parser()._actions for option in action.option_strings}
    assert all(feature.cli in parser_flags for feature in features if feature.cli != "always on")

    text = CATALOG_DOC.read_text(encoding="utf-8")
    documented_ids = re.findall(r"^\| (\d{2}\.\d{2}) \|", text, re.MULTILINE)
    assert documented_ids == ids
    for feature in features:
        row = next(line for line in text.splitlines() if line.startswith(f"| {feature.number} |"))
        assert len(row.strip("|").split("|")) == 6
        assert feature.name in row
        assert feature.cli in row or feature.cli == "always on" and "Always on" in row
        assert feature.field in row or feature.field in {"no_win_box", "hero_exp_cap", "convert_hex_guard", "dungeon_recom_info"} and "Built-in fix" in row
        variable = feature.variable or {"lan_redirect": "net_mode_var", "allow_unknown": "var_force"}.get(feature.field)
        assert (variable is None and "None" in row) or (variable is not None and f"`{variable}`" in row)


def test_grouped_options_render_once_when_display_available(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(MainWindow, "_initial_checks", lambda _window: None)
    try:
        window = MainWindow(project_root=tmp_path)
    except tk.TclError:
        pytest.skip("Tk display not available")
    try:
        window.geometry("980x720")
        window.update()

        def descendants(widget: tk.Misc):
            for child in widget.winfo_children():
                yield child
                yield from descendants(child)

        widgets = list(descendants(window))
        captions = [str(widget.cget("text")) for widget in widgets
                    if isinstance(widget, (tk.Label, tk.Checkbutton))]
        for group in FEATURE_GROUPS:
            assert f"{group.number}  {group.title}" in captions
            for feature in group.features:
                assert sum(text.startswith(feature.number + "  ") for text in captions) == 1
        for group in DEV_GROUPS:
            assert any(isinstance(widget, tk.LabelFrame) and
                       str(widget.cget("text")).strip() == f"{group.number}  {group.title}"
                       for widget in widgets)
            for feature in group.features:
                assert sum(text.startswith(feature.number + "  ") for text in captions) == 1

        numbered_checks = [widget for widget in widgets if isinstance(widget, tk.Checkbutton)
                           and re.match(r"^\d{2}\.\d{2}  ", str(widget.cget("text")))]
        assert all(widget.winfo_reqwidth() <= widget.winfo_width() for widget in numbered_checks)
        radios = [widget for widget in widgets if isinstance(widget, tk.Radiobutton)]
        assert all(widget.winfo_reqwidth() <= widget.winfo_width() for widget in radios)
        entries = [widget for widget in widgets if isinstance(widget, tk.Entry) and widget.winfo_ismapped()]
        # Path entries intentionally shrink with the window; ensure each visible
        # input still has room for several characters at the current DPI.
        for widget in entries:
            font = tkfont.Font(root=window, font=widget.cget("font"))
            assert widget.winfo_width() >= font.measure("0000")
        window.config_canvas.yview_moveto(1.0)
        window.update_idletasks()
        viewport_top = window.config_canvas.winfo_rooty()
        viewport_bottom = viewport_top + window.config_canvas.winfo_height()
        assert viewport_top <= window.btn_generate.winfo_rooty()
        assert window.btn_generate.winfo_rooty() + window.btn_generate.winfo_height() <= viewport_bottom
    finally:
        window.destroy()


def test_gui_defaults_collect_valid_conflict_free_patch_options(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    window = _build_headless_window(monkeypatch)
    options = window._collect_patch_options()

    # Must never trip mutual-exclusion or dev validation on default launch.
    validate_patch_options(options)

    assert options.limit_break_cost_fixed is True
    assert options.limit_break_cost_tenth is False
    assert options.summon_rates_50_30_20 is True
    assert options.summon_rates is False
    assert options.recycle_six_star is True
    assert options.stamina_cost_half is True
    assert options.gold_cylinder_x10 is True
    assert options.mana_cylinder_x10 is True
    assert options.battle_arena_save_fix is True
    assert options.guild_raid_mercenary is True
    assert options.guild_raid_fire_support is True
    assert options.guild_raid_protection_persist is True
    assert options.guild_raid_skills_max is True
    assert options.guild_raid_boss_no_counter is True
    assert options.align_16k is True
    assert options.alex_rebalance is True
    assert options.worldboss_full_ship_repair is True


def test_gui_option_vars_wire_all_features_and_preserve_exclusions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    window = _build_headless_window(monkeypatch)

    # Every mutually exclusive toggle keeps collected PatchOptions valid.
    for attr in (
        "var_summon",
        "var_summon_50_30_20",
        "var_battle_arena_save_fix",
        "var_guild_raid_mercenary",
        "var_limit_break_cost_fixed",
    ):
        getattr(window, attr).set(True)
        validate_patch_options(window._collect_patch_options())

    # Toggling each GUI option variable updates its exact PatchOptions field.
    var_to_field: list[tuple[str, str, object]] = [
        ("var_gold", "campaign_gold", True),
        ("var_xp", "campaign_xp", True),
        ("var_no_equip_drops", "no_equip_drops", True),
        ("var_gene", "gene_priority", True),
        ("var_summon", "summon_rates", True),
        ("var_summon_50_30_20", "summon_rates_50_30_20", True),
        ("var_expedition", "expedition_bonus", True),
        ("var_english", "english_localization", True),
        ("var_event_discount", "event_discount", True),
        ("var_event_gene_unlimited", "event_gene_unlimited", True),
        ("var_event_limits_daily", "event_limits_daily", True),
        ("var_mythical_stone_shop", "mythical_stone_shop", True),
        ("var_hero_shop_offers", "hero_shop_offers", True),
        ("var_surprise_transcendence_package", "surprise_transcendence_package", True),
        ("var_costume_packages_all", "costume_packages_all", True),
        ("var_recycle_six_star", "recycle_six_star", True),
        ("var_campaign_shop_discount", "campaign_shop_discount", True),
        ("var_mode_drops_x10", "mode_drops_x10", True),
        ("var_devil_boost_x10", "devil_boost_x10", True),
        ("var_battle_arena_fix", "battle_arena_fix", True),
        ("var_guild_raid_mercenary", "guild_raid_mercenary", True),
        ("var_guild_raid_reward_x10", "guild_raid_reward_x10", True),
        ("var_energy_flask_x10", "energy_flask_x10", True),
        ("var_option_max_attributes", "option_max_attributes", True),
        ("var_rune_box_random_type", "rune_box_random_type", True),
        ("var_rune_box_random_roll", "rune_box_random_roll", True),
        ("var_equipment_lock_fix", "equipment_lock_fix", True),
        ("var_equipment_single_mod_stone", "equipment_single_mod_stone", True),
        ("var_equipment_percent_options", "equipment_percent_options", True),
        ("var_equipment_upgrade_10_guarantee", "equipment_upgrade_10_guarantee", True),
        ("var_soulgear_enchant_always", "soulgear_enchant_always", True),
        ("var_rune_quality_x10", "rune_quality_factor", 10),
        ("var_rune_option_quality", "rune_option_quality", True),
        ("var_gold_cylinder_x10", "gold_cylinder_x10", True),
        ("var_mana_cylinder_x10", "mana_cylinder_x10", True),
        ("var_event_coin_x10", "event_coin_x10", True),
        ("var_guild_raid_score_fix", "guild_raid_score_fix", True),
        ("var_guild_raid_fire_support", "guild_raid_fire_support", True),
        ("var_guild_raid_protection_persist", "guild_raid_protection_persist", True),
        ("var_guild_raid_skills_max", "guild_raid_skills_max", True),
        ("var_guild_raid_boss_no_counter", "guild_raid_boss_no_counter", True),
        ("var_single_black_hammer", "single_black_hammer", True),
        ("var_single_gem_fang", "single_gem_fang", True),
        ("var_upgrade_no_fail_above_20", "upgrade_no_fail_above_20", True),
        ("var_battle_arena_save_fix", "battle_arena_save_fix", True),
        ("var_sacred_lands_restore", "sacred_lands_restore", True),
        ("var_coocoo_exp_x2", "coocoo_exp_x2", True),
        ("var_coocoo_level_x2", "coocoo_level_x2", True),
        ("var_ship_parts_90_off", "ship_parts_90_off", True),
        ("var_worldboss_full_ship_repair", "worldboss_full_ship_repair", True),
        ("var_crystal_skill_90_off", "crystal_skill_90_off", True),
        ("var_gem_mining_x10", "gem_mining_x10", True),
        ("var_gem_mining_types", "gem_mining_types", True),
        ("var_gem_level6", "gem_level6", True),
        ("var_gem_upgrade_gold_half", "gem_upgrade_gold_half", True),
        ("var_stamina_cost_half", "stamina_cost_half", True),
        ("var_stamina_potion_1000", "stamina_potion_1000", True),
        ("var_align_16k", "align_16k", True),
        ("var_alex_rebalance", "alex_rebalance", True),
        ("var_trait_max_quality", "trait_max_quality", True),
        ("var_trait_allow_duplicates", "trait_allow_duplicates", True),
        ("var_trait_multi_unique", "trait_multi_unique", True),
        ("var_trait_immunity_weight_x2", "trait_immunity_weight_x2", True),
        ("var_limit_break_step_10", "limit_break_step_10", True),
        ("var_merlin_auto_support", "merlin_auto_support", True),
    ]
    for var_attr, field_name, enabled_val in var_to_field:
        var = getattr(window, var_attr)
        var.set(False)
        off_opts = window._collect_patch_options()
        assert getattr(off_opts, field_name) in (False, 0)
        var.set(True)
        on_opts = window._collect_patch_options()
        validate_patch_options(on_opts)
        assert getattr(on_opts, field_name) == enabled_val
