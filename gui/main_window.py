#!/usr/bin/env python3
"""FWT Reborn - Desktop Patcher Application Main Window."""

from __future__ import annotations

import contextlib
import ipaddress
import os
import queue
import sys
import threading
import tkinter as tk
import webbrowser
from collections.abc import Callable, Sequence
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk
from typing import Any, Literal, Optional, Protocol

from core.apk_tooling import (
    AdbHelper,
    locate_tools,
    repack_and_sign_apk,
)
from core.core_patches import (
    DEV_OUTPUT_SUFFIX,
    DevOptions,
    PatchOptions,
    is_dev_output_path,
    validate_patch_options,
)
from core.patch_inspector import inspect_apk, verify_report
from core.version import (
    APP_BASE_GAME,
    APP_DESCRIPTION,
    APP_DISCLAIMER,
    APP_LICENSE,
    APP_NAME,
    APP_RELEASE_DATE,
    APP_REPO_URL,
    APP_VERSION,
    APP_VERSION_DISPLAY,
    versioned_output_path,
)
from gui.components import FilePathPicker, LogViewer, StatusBadge
from gui.feature_catalog import DEV_GROUPS, FEATURE_GROUPS, feature_by_field
from gui.theme import (
    ACCENT_AMBER,
    ACCENT_BLUE,
    ACCENT_BLUE_HOVER,
    ACCENT_CYAN,
    ACCENT_GREEN,
    ACCENT_GREEN_HOVER,
    ACCENT_PURPLE,
    ACCENT_RED,
    BG_BORDER,
    BG_CARD,
    BG_INPUT,
    BG_MAIN,
    FONT_FAMILY,
    FONT_MONO,
    PAD_LG,
    PAD_MD,
    PAD_SM,
    TEXT_MUTED,
    TEXT_PRIMARY,
    TEXT_SECONDARY,
)


class BoolVarLike(Protocol):
    """Minimal BooleanVar interface shared by Tk variables and headless test doubles."""

    def get(self) -> bool: ...
    def set(self, value: bool) -> None: ...
    def trace_add(
        self,
        mode: Literal["array", "read", "write", "unset"],
        callback: Callable[[str, str, str], object],
    ) -> str: ...


def _bind_clear_rules(
    rules: Sequence[tuple[BoolVarLike, tuple[BoolVarLike, ...]]],
) -> None:
    """Wire write traces that clear ``targets`` whenever ``source`` becomes True."""
    syncing = False

    def _on_write(source: BoolVarLike, targets: tuple[BoolVarLike, ...]) -> None:
        nonlocal syncing
        if syncing or not source.get():
            return
        syncing = True
        try:
            for target in targets:
                if target is not source and target.get():
                    target.set(False)
        finally:
            syncing = False

    for source, targets in rules:
        source.trace_add(
            "write",
            lambda *_args, src=source, dst=targets: _on_write(src, dst),
        )


def bind_exclusive_var_group(*variables: BoolVarLike) -> None:
    """Keep at most one BooleanVar in ``variables`` True at any time."""
    all_vars = tuple(variables)
    _bind_clear_rules([(var, all_vars) for var in all_vars])


def bind_exclusive_master_var(
    master: BoolVarLike, *conflicts: BoolVarLike
) -> None:
    """Keep ``master`` mutually exclusive with every variable in ``conflicts``.

    Enabling ``master`` clears all enabled ``conflicts``; enabling any
    conflict clears ``master`` while leaving the other conflicts intact.
    """
    conflict_tuple = tuple(conflicts)
    rules: list[tuple[BoolVarLike, tuple[BoolVarLike, ...]]] = [
        (master, conflict_tuple)
    ]
    rules.extend((conflict, (master,)) for conflict in conflict_tuple)
    _bind_clear_rules(rules)


class MainWindow(tk.Tk):
    """Main Application Window for FWT Reborn Client Patcher."""

    def __init__(self, project_root: Optional[Path] = None):
        if os.name == "nt":
            try:
                import ctypes

                windll = getattr(ctypes, "windll", None)
                if windll is not None:
                    windll.shcore.SetProcessDpiAwareness(1)
            except Exception:
                pass
        super().__init__()
        self.project_root = project_root or Path(__file__).resolve().parents[1]

        try:
            from dotenv import load_dotenv

            load_dotenv(self.project_root / ".env", override=False)
        except ImportError:
            pass

        # Paths (respect .env overrides while keeping project-relative defaults)
        source_env = os.environ.get("FWT_SOURCE_APK", "source/fwt_0.682_offline_v1574.apk")
        output_env = os.environ.get("FWT_OUTPUT_APK", "output/FWT-Reborn-Patched.apk")
        keystore_env = os.environ.get("FWT_KEYSTORE", "keystore/fwt_reborn_lan.jks")
        self.default_source = (self.project_root / source_env).expanduser()
        self.default_output = versioned_output_path(
            (self.project_root / output_env).expanduser(), dev=False
        )
        self.keystore_path = (self.project_root / keystore_env).expanduser()
        self.backups_dir = self.project_root / "backups"

        # Tools & ADB
        self.tools = locate_tools()
        self.adb = AdbHelper(self.tools.adb)
        self.devices: list[dict[str, str]] = []
        self.is_busy = False
        self.device_op_active = False
        self._close_requested = False
        self._cancel_event = threading.Event()

        # Thread-safe bridge: worker threads enqueue callables, the Tk main
        # thread executes them in _drain_ui_queue(). Never call messagebox or
        # read Tk variables from a worker thread.
        self._ui_queue: queue.Queue = queue.Queue()
        self.after(50, self._drain_ui_queue)

        # Window Config
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.title(f"{APP_NAME} {APP_VERSION_DISPLAY} - Offline Client Patcher")
        self.geometry("1100x820")
        self.minsize(980, 720)
        self.configure(bg=BG_MAIN)

        # Style configuration
        self._init_styles()
        self._build_menu()

        # Build UI layout
        self._build_header()
        self._build_body()
        self._build_footer()

        # Initial background tasks
        self.after(200, self._initial_checks)

    # -----------------------------------------------------------------------
    # Thread-safe UI helpers
    # -----------------------------------------------------------------------
    def post_ui(self, callback, *args, **kwargs) -> None:
        """Enqueue a callable for execution on the Tk main thread."""
        self._ui_queue.put((callback, args, kwargs))

    def _drain_ui_queue(self) -> None:
        try:
            while True:
                callback, args, kwargs = self._ui_queue.get_nowait()
                try:
                    callback(*args, **kwargs)
                except Exception as exc:
                    self.log_viewer.log(f"UI callback error: {exc}", "error")
        except queue.Empty:
            pass
        with contextlib.suppress(tk.TclError):
            self.after(50, self._drain_ui_queue)

    def _init_styles(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure(
            "TCombobox",
            fieldbackground=BG_INPUT,
            background=BG_BORDER,
            foreground=TEXT_PRIMARY,
            darkcolor=BG_BORDER,
            lightcolor=BG_BORDER,
        )
        style.map(
            "TCombobox",
            fieldbackground=[("readonly", BG_INPUT)],
            selectbackground=[("readonly", ACCENT_BLUE)],
            selectforeground=[("readonly", "#ffffff")],
        )

    def _build_menu(self):
        menubar = tk.Menu(self, tearoff=0)
        about_menu = tk.Menu(menubar, tearoff=0)
        about_menu.add_command(
            label=f"About {APP_NAME}",
            command=self._show_about,
        )
        about_menu.add_command(label="Open Changelog", command=self._show_changelog)
        about_menu.add_command(
            label="Open Repository",
            command=lambda: webbrowser.open(APP_REPO_URL),
        )
        about_menu.add_separator()
        about_menu.add_command(label="Exit", command=self._on_close)
        menubar.add_cascade(label="About", menu=about_menu)
        self.config(menu=menubar)

    def _show_about(self) -> None:
        about = tk.Toplevel(self)
        about.title(f"About {APP_NAME}")
        about.geometry("640x600")
        about.minsize(560, 480)
        about.configure(bg=BG_MAIN)
        about.transient(self)
        about.grab_set()

        header = tk.Label(
            about,
            text=f"{APP_NAME} {APP_VERSION_DISPLAY}",
            font=(FONT_FAMILY, 18, "bold"),
            bg=BG_MAIN,
            fg=TEXT_PRIMARY,
        )
        header.pack(anchor="w", padx=PAD_LG, pady=(PAD_LG, 2))

        subtitle = tk.Label(
            about,
            text=f"{APP_DESCRIPTION}",
            font=(FONT_FAMILY, 9),
            bg=BG_MAIN,
            fg=TEXT_SECONDARY,
            wraplength=590,
            justify="left",
        )
        subtitle.pack(anchor="w", padx=PAD_LG, pady=(0, PAD_MD))

        body = tk.Frame(about, bg=BG_CARD, bd=1, relief="solid")
        body.pack(fill="both", expand=True, padx=PAD_LG, pady=PAD_SM)

        info = tk.Text(
            body,
            wrap="word",
            bg=BG_CARD,
            fg=TEXT_PRIMARY,
            insertbackground=TEXT_PRIMARY,
            relief="flat",
            bd=0,
            padx=PAD_MD,
            pady=PAD_MD,
            font=(FONT_FAMILY, 9),
            height=20,
        )
        info.pack(fill="both", expand=True, side="left")
        scrollbar = tk.Scrollbar(body, orient="vertical", command=info.yview)
        scrollbar.pack(side="right", fill="y")
        info.configure(yscrollcommand=scrollbar.set)

        lines = [
            f"Version: {APP_VERSION}",
            f"Released: {APP_RELEASE_DATE}",
            f"Base game: {APP_BASE_GAME}",
            f"License: {APP_LICENSE}",
            f"Repository: {APP_REPO_URL}",
            f"Python: {sys.version.split()[0]}",
            f"Tk: {self.tk.call('info', 'patchlevel')}",
            "",
            "Main features:",
            "  - 10x campaign gold, drops and XP",
            "  - 10x expedition and six game-mode drops",
            "  - Event Shop discount, unlimited genes and daily event limits",
            "  - Equipment, rune, soulgear and limit break upgrades",
            "  - Laboratory x10 rewards, stamina and savegame tooling",
            "  - APK inspection, 16 KB alignment and signing",
            "",
            "Disclaimer:",
            APP_DISCLAIMER,
        ]
        info.insert("1.0", "\n".join(lines))
        info.configure(state="disabled")

        buttons = tk.Frame(about, bg=BG_MAIN)
        buttons.pack(fill="x", padx=PAD_LG, pady=(PAD_SM, PAD_LG))

        def button(text: str, command, color: str) -> tk.Button:
            return tk.Button(
                buttons,
                text=text,
                command=command,
                font=(FONT_FAMILY, 9, "bold"),
                bg=color,
                fg="#ffffff",
                activebackground=color,
                activeforeground="#ffffff",
                bd=0,
                padx=12,
                pady=5,
                cursor="hand2",
            )

        button("Changelog", self._show_changelog, ACCENT_BLUE).pack(side="left", padx=(0, PAD_SM))
        button(
            "Repository",
            lambda: webbrowser.open(APP_REPO_URL),
            ACCENT_PURPLE,
        ).pack(side="left", padx=(0, PAD_SM))
        button("Close", about.destroy, BG_BORDER).pack(side="right")

    def _show_changelog(self) -> None:
        changelog = self.project_root / "CHANGELOG.md"
        if not changelog.is_file():
            messagebox.showinfo(
                "Changelog",
                "CHANGELOG.md was not found in the project root.",
                parent=self,
            )
            return

        window = tk.Toplevel(self)
        window.title(f"{APP_NAME} - Changelog")
        window.geometry("760x620")
        window.minsize(600, 420)
        window.configure(bg=BG_MAIN)
        window.transient(self)

        text = tk.Text(
            window,
            wrap="word",
            bg=BG_CARD,
            fg=TEXT_PRIMARY,
            insertbackground=TEXT_PRIMARY,
            relief="flat",
            bd=0,
            padx=PAD_MD,
            pady=PAD_MD,
            font=(FONT_MONO, 9),
        )
        text.pack(fill="both", expand=True, side="left", padx=(PAD_MD, 0), pady=PAD_MD)
        scrollbar = tk.Scrollbar(window, orient="vertical", command=text.yview)
        scrollbar.pack(side="right", fill="y", padx=(0, PAD_MD), pady=PAD_MD)
        text.configure(yscrollcommand=scrollbar.set)
        text.insert("1.0", changelog.read_text(encoding="utf-8", errors="replace"))
        text.configure(state="disabled")

    def _build_header(self):
        header = tk.Frame(self, bg=BG_CARD, bd=1, relief="solid")
        header.pack(fill="x", padx=PAD_MD, pady=(PAD_MD, PAD_SM))

        inner = tk.Frame(header, bg=BG_CARD)
        inner.pack(fill="x", padx=PAD_LG, pady=PAD_MD)

        # Title & Subtitle
        left_col = tk.Frame(inner, bg=BG_CARD)
        left_col.pack(side="left")

        title = tk.Label(
            left_col,
            text=f"FWT Reborn - Client Patcher  {APP_VERSION_DISPLAY}",
            font=(FONT_FAMILY, 16, "bold"),
            bg=BG_CARD,
            fg=TEXT_PRIMARY,
        )
        title.pack(anchor="w")

        subtitle = tk.Label(
            left_col,
            text="Autonomous Offline Feature Injector, APK Alignment, and Savegame Backup",
            font=(FONT_FAMILY, 9),
            bg=BG_CARD,
            fg=TEXT_SECONDARY,
        )
        subtitle.pack(anchor="w")

        version_line = tk.Label(
            left_col,
            text=f"{APP_BASE_GAME}  |  {APP_LICENSE}  |  Released {APP_RELEASE_DATE}",
            font=(FONT_FAMILY, 8),
            bg=BG_CARD,
            fg=ACCENT_AMBER,
        )
        version_line.pack(anchor="w", pady=(2, 0))

        # Badges & Status on Right
        right_col = tk.Frame(inner, bg=BG_CARD)
        right_col.pack(side="right")

        self.badge_tools = StatusBadge(right_col, text="Checking Tools...", active=False)
        self.badge_tools.pack(side="right", padx=4)

        self.badge_adb = StatusBadge(right_col, text="ADB: Searching...", active=False)
        self.badge_adb.pack(side="right", padx=4)

        self.lbl_dev_badge = tk.Label(
            right_col,
            text="",
            font=(FONT_FAMILY, 9, "bold"),
            bg=BG_CARD,
            fg=ACCENT_AMBER,
        )
        self.lbl_dev_badge.pack(side="right", padx=(4, 8))

    def _build_body(self):
        body = tk.Frame(self, bg=BG_MAIN)
        body.pack(fill="both", expand=True, padx=PAD_MD, pady=PAD_SM)

        # Left Column: Configuration & Actions
        left_shell = tk.Frame(body, bg=BG_MAIN)
        left_shell.pack(side="left", fill="both", expand=True, padx=(0, PAD_SM))
        self.config_canvas = tk.Canvas(left_shell, bg=BG_MAIN, highlightthickness=0)
        config_scrollbar = tk.Scrollbar(left_shell, orient="vertical", command=self.config_canvas.yview)
        self.config_canvas.configure(yscrollcommand=config_scrollbar.set)
        self.config_canvas.pack(side="left", fill="both", expand=True)
        config_scrollbar.pack(side="right", fill="y")
        left_pane = tk.Frame(self.config_canvas, bg=BG_MAIN)
        config_window = self.config_canvas.create_window((0, 0), window=left_pane, anchor="nw")
        left_pane.bind("<Configure>", lambda _event: self.config_canvas.configure(
            scrollregion=self.config_canvas.bbox("all")
        ))
        self._numbered_checkbuttons: list[tk.Checkbutton] = []

        def _resize_config(event: Any) -> None:
            self.config_canvas.itemconfig(config_window, width=event.width)
            for checkbox in self._numbered_checkbuttons:
                checkbox.configure(wraplength=max(180, event.width - 75))

        self.config_canvas.bind("<Configure>", _resize_config)

        def _scroll_config(event: Any, units: int) -> None:
            hovered = self.config_canvas.winfo_containing(event.x_root, event.y_root)
            if hovered is None:
                return
            feature_grid = getattr(self, "_feature_grid_frame", None)
            feature_canvas = getattr(self, "_feature_canvas", None)
            if hovered == feature_canvas or (feature_grid is not None and
                    str(hovered).startswith(str(feature_grid))):
                return
            if hovered == self.config_canvas or str(hovered).startswith(str(left_pane)):
                self.config_canvas.yview_scroll(units, "units")

        self.bind_all("<MouseWheel>", lambda event: _scroll_config(
            event, int(-event.delta / 120) if abs(event.delta) >= 120 else (-1 if event.delta > 0 else 1)
        ), add="+")
        self.bind_all("<Button-4>", lambda event: _scroll_config(event, -3), add="+")
        self.bind_all("<Button-5>", lambda event: _scroll_config(event, 3), add="+")

        # Right Column: Console Log Viewer
        right_pane = tk.Frame(body, bg=BG_MAIN)
        right_pane.pack(side="right", fill="both", expand=True, padx=(PAD_SM, 0))

        # ----------------- Left Pane Content -----------------
        # 1. APK File Pickers & Inspection Summary Card
        self._build_apk_section(left_pane)

        # 2. Patch Toggles Card
        self._build_options_section(left_pane)

        # 3. Development Card (dev-only instrumentation)
        self._build_dev_section(left_pane)

        # 4. ADB & Device Section Card
        self._build_adb_section(left_pane)

        # 5. Action Buttons Card
        self._build_actions_section(left_pane)

        # ----------------- Right Pane Content -----------------
        self.log_viewer = LogViewer(right_pane)
        self.log_viewer.pack(fill="both", expand=True)

    def _build_apk_section(self, parent: tk.Widget):
        card = tk.LabelFrame(
            parent,
            text=" 1. APK Selection & Verification ",
            font=(FONT_FAMILY, 10, "bold"),
            bg=BG_CARD,
            fg=ACCENT_CYAN,
            bd=1,
            relief="solid",
            padx=PAD_MD,
            pady=PAD_SM,
        )
        card.pack(fill="x", pady=(0, PAD_SM))

        self.in_picker = FilePathPicker(
            card,
            label="Base Offline APK:",
            default_path=str(self.default_source) if self.default_source.is_file() else "",
            file_types=[("Android APK", "*.apk"), ("All Files", "*.*")],
            on_change=lambda _: self._update_apk_info(),
        )
        self.in_picker.pack(fill="x", pady=(0, 4))

        # Inspection & Status Row
        status_row = tk.Frame(card, bg=BG_CARD)
        status_row.pack(fill="x", pady=4)

        self.btn_inspect = tk.Button(
            status_row,
            text="🔍 Inspect / Verify APK",
            command=self.inspect_base_apk,
            font=(FONT_FAMILY, 9, "bold"),
            bg=ACCENT_BLUE,
            fg="#ffffff",
            activebackground=ACCENT_BLUE_HOVER,
            activeforeground="#ffffff",
            bd=0,
            padx=12,
            pady=4,
            cursor="hand2",
        )
        self.btn_inspect.pack(side="left", padx=(0, PAD_SM))

        self.lbl_inspection_status = tk.Label(
            status_row,
            text="Ready to inspect APK",
            font=(FONT_FAMILY, 9),
            bg=BG_CARD,
            fg=TEXT_MUTED,
        )
        self.lbl_inspection_status.pack(side="left", fill="x", expand=True)

        self.out_picker = FilePathPicker(
            card,
            label="Output Patched APK:",
            default_path=str(self.default_output),
            file_types=[("Android APK", "*.apk"), ("All Files", "*.*")],
            is_save=True,
        )
        self.out_picker.pack(fill="x", pady=(4, 0))

        self.var_force = tk.BooleanVar(value=False)
        self.chk_force = tk.Checkbutton(
            card,
            text=f"{feature_by_field('allow_unknown').number}  Allow non-reference APK (advanced; may corrupt the output)",
            variable=self.var_force,
            font=(FONT_FAMILY, 8),
            bg=BG_CARD,
            fg=ACCENT_AMBER,
            selectcolor=BG_INPUT,
            activebackground=BG_CARD,
            activeforeground=ACCENT_AMBER,
            justify="left",
            wraplength=300,
        )
        self.chk_force.pack(anchor="w", pady=(4, 0))
        self._numbered_checkbuttons.append(self.chk_force)

    def _build_options_section(self, parent: tk.Widget):
        card = tk.LabelFrame(
            parent,
            text=" 2. Custom Patch Features ",
            font=(FONT_FAMILY, 10, "bold"),
            bg=BG_CARD,
            fg=ACCENT_CYAN,
            bd=1,
            relief="solid",
            padx=PAD_MD,
            pady=PAD_SM,
        )
        card.pack(fill="x", pady=(0, PAD_SM))

        self._init_option_vars()
        self._bind_option_exclusions()
        self._populate_options_card(card)

    def _init_option_vars(self) -> None:
        # Checkbox variables
        self.var_gold = tk.BooleanVar(value=True)
        self.var_xp = tk.BooleanVar(value=True)
        self.var_no_equip_drops = tk.BooleanVar(value=True)
        self.var_gene = tk.BooleanVar(value=True)
        self.var_summon = tk.BooleanVar(value=False)
        self.var_summon_50_30_20 = tk.BooleanVar(value=True)
        self.var_expedition = tk.BooleanVar(value=True)
        self.var_english = tk.BooleanVar(value=True)
        self.var_event_discount = tk.BooleanVar(value=True)
        self.var_event_gene_unlimited = tk.BooleanVar(value=True)
        self.var_event_limits_daily = tk.BooleanVar(value=True)
        self.var_mythical_stone_shop = tk.BooleanVar(value=True)
        self.var_hero_shop_offers = tk.BooleanVar(value=True)
        self.var_alex_awakening = tk.BooleanVar(value=True)
        self.var_alex_rebalance = tk.BooleanVar(value=True)
        self.var_costume_packages_all = tk.BooleanVar(value=True)
        self.var_recycle_six_star = tk.BooleanVar(value=True)
        self.var_campaign_shop_discount = tk.BooleanVar(value=True)
        self.var_mode_drops_x10 = tk.BooleanVar(value=True)
        self.var_devil_boost_x10 = tk.BooleanVar(value=True)
        self.var_battle_arena_fix = tk.BooleanVar(value=True)
        self.var_guild_raid_mercenary = tk.BooleanVar(value=True)
        self.var_guild_raid_reward_x10 = tk.BooleanVar(value=True)
        self.var_energy_flask_x10 = tk.BooleanVar(value=True)
        self.var_option_max_attributes = tk.BooleanVar(value=True)
        self.var_rune_box_random_type = tk.BooleanVar(value=True)
        self.var_rune_box_random_roll = tk.BooleanVar(value=True)
        self.var_equipment_lock_fix = tk.BooleanVar(value=True)
        self.var_equipment_single_mod_stone = tk.BooleanVar(value=True)
        self.var_equipment_percent_options = tk.BooleanVar(value=True)
        self.var_equipment_upgrade_10_guarantee = tk.BooleanVar(value=True)
        self.var_limit_break_cost_tenth = tk.BooleanVar(value=False)
        self.var_limit_break_cost_fixed = tk.BooleanVar(value=True)
        self.var_soulgear_enchant_always = tk.BooleanVar(value=True)
        self.var_rune_quality_x10 = tk.BooleanVar(value=True)
        self.var_rune_option_quality = tk.BooleanVar(value=True)
        self.var_rune_upgrade_discount = tk.BooleanVar(value=True)
        self.var_gold_cylinder_x10 = tk.BooleanVar(value=True)
        self.var_mana_cylinder_x10 = tk.BooleanVar(value=True)
        self.var_event_coin_x10 = tk.BooleanVar(value=True)
        self.var_guild_raid_score_fix = tk.BooleanVar(value=True)
        self.var_guild_raid_fire_support = tk.BooleanVar(value=True)
        self.var_guild_raid_skills_max = tk.BooleanVar(value=True)
        self.var_guild_raid_boss_no_counter = tk.BooleanVar(value=True)
        self.var_single_black_hammer = tk.BooleanVar(value=True)
        self.var_equipment_tier_upgrades = tk.BooleanVar(value=True)
        self.var_single_gem_fang = tk.BooleanVar(value=True)
        self.var_upgrade_no_fail_above_20 = tk.BooleanVar(value=True)
        self.var_battle_arena_save_fix = tk.BooleanVar(value=True)
        self.var_sacred_lands_restore = tk.BooleanVar(value=True)
        self.var_coocoo_exp_x2 = tk.BooleanVar(value=True)
        self.var_coocoo_level_x2 = tk.BooleanVar(value=True)
        self.var_ship_parts_90_off = tk.BooleanVar(value=True)
        self.var_crystal_skill_90_off = tk.BooleanVar(value=True)
        self.var_gem_mining_x10 = tk.BooleanVar(value=True)
        self.var_gem_mining_types = tk.BooleanVar(value=True)
        self.var_gem_level6 = tk.BooleanVar(value=True)
        self.var_gem_upgrade_gold_half = tk.BooleanVar(value=True)
        self.var_stamina_cost_half = tk.BooleanVar(value=True)
        self.var_stamina_potion_1000 = tk.BooleanVar(value=True)
        self.var_align_16k = tk.BooleanVar(value=True)

    def _bind_option_exclusions(self) -> None:
        bind_exclusive_var_group(self.var_summon, self.var_summon_50_30_20)
        bind_exclusive_var_group(
            self.var_limit_break_cost_tenth, self.var_limit_break_cost_fixed
        )

    def _populate_options_card(self, card: tk.LabelFrame) -> None:
        options = [
            (self.var_gold, "10x Campaign Gold & Drops", "Multiplies gold, stamina, items, mana, and gene drop quantities by 10x"),
            (self.var_xp, "10x Campaign XP", "Multiplies campaign hero XP and Lord XP by 10x for faster character growth"),
            (self.var_no_equip_drops, "Remove Equipment Drops", "Removes equipment from stage drop pools and redistributes their weight to other drops in the stage"),
            (self.var_gene, "Hero Gene Drop Priority", "Prioritizes hero genes over regular items across all map stages"),
            (self.var_summon, "Equipment Summon Rates (70/20/10)", "Rebalances equipment pools to 70% 4★, 20% 5★, and 10% 6★ (0% 1★-3★)"),
            (self.var_summon_50_30_20, "Equipment Summon Rates (50/30/20)", "Rebalances equipment pools to 50% 4★, 30% 5★, and 20% 6★ (alternative profile)"),
            (self.var_expedition, "10x Expedition Rewards", "Multiplies hero XP and settlement rewards by 10x (crystals, mana, coins, genes, items)"),
            (self.var_english, "English Localization Unlock", "Sets US Locale, translates server loading/bootstrap UI, and bypasses Korean string table and message box gates"),
            (self.var_event_discount, "90% Event Shop Discount", "Reduces all 122 event shop items' coin costs by 90%"),
            (self.var_event_gene_unlimited, "Unlimited Event Shop Genes", "Removes Event Shop gene purchase limits (unlimited)"),
            (self.var_event_limits_daily, "Daily Event Shop Limits", "Converts event-limited items (3 per event, etc.) to daily resets while keeping their original per-day quantity"),
            (self.var_mythical_stone_shop, "Mythical Stone in Event Shop", "Offers Mythical Stone for 50 event coins, 100 per day; Balance Jade remains available 20 times daily"),
            (self.var_hero_shop_offers, "Evan and Alex Shop Offers", "Unlimited Evan genes for 5 event coins and Alex genes for 1 medal; 100 Diamonds"),
            (self.var_alex_awakening, "Alex Awakening: Destiny Lance", "Awaken Alex and unlock Destiny Lance, which damages and swaps places with a boss anywhere on the map"),
            (self.var_alex_rebalance, "Alex Skill, Passive & Awake Rebalance", "Rebalances Alex Skills 1-3, Passive (Knighthood), and upgrades Destiny Lance to create permanent 1-cell Thornbush around the Boss's destination"),
            (self.var_costume_packages_all, "Complete Costume Packages", "Packages 3 and 4 each give one copy of every eligible owned costume; up to 10 purchases per package daily"),
            (self.var_recycle_six_star, "Recycling Grants 6★ Equipment", "Keeps the native equipment grant and turns all alchemy reward rows into a 6★ piece (grade 5 + secret grade 3, e.g. Absolute Gavel of Defense)"),
            (self.var_campaign_shop_discount, "90% Campaign Shop Discount", "90% discount across campaign shops (Honor, Ancient Coins, Guild Raid, Unknown Paradise, and Friend Shop)"),
            (self.var_mode_drops_x10, "10x Mode Drops", "10x drops across 6 game modes (Unknown Paradise, Battle of Honor, Dimension Breakthrough, Pit of Nephthys, Sky Library, Lost Island). Dimension genes are guaranteed and x10; Battle of Honor rank points are x2 on victory."),
            (self.var_devil_boost_x10, "10x Devil's Soul EXP Boost", "When a Devil's Soul is used in EXP synthesis, the native 2x EXP bonus becomes 20x"),
            (self.var_battle_arena_fix, "Battle Arena Team Save Fix", "Fixes Battle Arena/PvP team saving: compacts the client's eight members (four pairs) to the four team leaders for REQ_REGISTER_PVP and SET_DEFENSE_TEAM_PVP, plus the week-state and empty-slot fixes"),
            (self.var_guild_raid_mercenary, "Guild Raid Self-Mercenary", "Uses today's configured hero with their equipment; falls back to the selected guild member if no valid hero is configured"),
            (self.var_guild_raid_reward_x10, "Guild Raid Reward x10", "Multiplies the Guild Raid daily and weekly rank reward mails (item 150001, gold and the secondary reward) by 10"),
            (self.var_energy_flask_x10, "Energy Flask x10 Stamina", "The Energy Flask awards 1000 stamina instead of 100 on each collection (windows unchanged)"),
            (self.var_option_max_attributes, "Option Rolls: Max Quality", "Every equipment option roll (potion, granted gear and re-roll) lands on the best value available for the attribute and the equipment grade; locked lines keep the stock handling"),
            (self.var_rune_box_random_type, "Rune Box: Random Type", "The 4-star random rune box rolls any of the three basic rune types (the stock table points it at a single type the roll rejects)"),
            (self.var_limit_break_cost_tenth, "Awake: 90% Cheaper Limit Break", "Creature transcend above level 70 charges a tenth of the gold and evolution items"),
            (self.var_limit_break_cost_fixed, "Awake: Fixed Limit Break Cost", "Every hero limit break costs a flat 1,000,000 gold and 100 Balance Jade, so the price no longer grows with the level (overrides the 90% discount)"),
            (self.var_soulgear_enchant_always, "Soulgear: Enchant Always Succeeds", "The gold-paid soulgear enchant skips its 84.75%..6% roll (the upgrade path has no roll)"),
            (self.var_equipment_lock_fix, "Equipment: Locks Hold on the First Roll", "The option handler re-rolled the whole set before reading lock_list, so a locked line came back with a fresh value; with this on the locked lines survive"),
            (self.var_equipment_single_mod_stone, "Equipment: 1 Modification Stone", "Every attribute re-roll costs one Modification Stone, even with two or three locked lines (the stock formula charges 2 and 4)"),
            (self.var_equipment_percent_options, "Equipment: Percentage Options Only", "Removes the flat option rows (+100 Crit, +50 HP) from the roll; only percentage attributes (+10% Crit Rate, +2% HP) are drawn"),
            (self.var_equipment_upgrade_10_guarantee, "+10 Upgrade Always Succeeds", "Makes the +9 to +10 equipment upgrade succeed on the first attempt; +21..+26 keep their own option"),
            (self.var_rune_box_random_roll, "Rune Box: Random Slot/Type (real RNG)", "Reroutes the box's slot and type rolls through a counter, so purchases stop repeating the same rune. Grade, quality and the fourth attribute stay deterministic as the dev designed"),
            (self.var_rune_quality_x10, "Rune Attributes: 10x Mastery Bias + Percent Only", "Rune attribute rolls multiply the Lord mastery bias by 10 (450 -> 4500 out of 10000) and exclude fixed-value attributes. Rune slot and fourth-attribute rules are preserved."),
            (self.var_rune_option_quality, "Rune Options: Max Quality", "Rune rolls always use the maximum Lord mastery weight row"),
            (self.var_rune_upgrade_discount, "Rune Upgrade: Guaranteed +12..+15 (90% Off)", "Levels +12 to +15 never fail and charge a tenth of the gold; the Awake screen shows the discounted price"),
            (self.var_gold_cylinder_x10, "Gold Cylinder x10 Gold", "The Gold Cylinder yields ten times the gold per collection (the tool's own level XP also scales)"),
            (self.var_mana_cylinder_x10, "Mana Stone Compactor x10 Mana", "The Mana Stone Compactor yields ten times the mana per charge (the tool's own level XP also scales)"),
            (self.var_event_coin_x10, "10x Campaign Event Coin Drop", "Multiplies event coin battle rewards by 10x in map stages"),
            (self.var_guild_raid_score_fix, "Guild Raid 64-bit Scores (>2.5B)", "Fixes the start-response overflow so Guild Raid records above 2.5B can load and settle"),
            (
                self.var_guild_raid_fire_support,
                "Guild Raid Fire Support (100% HP + Odd Turns)",
                "Sets Fire Support minion damage to 100% maxHp and holds active/reserved auto-cast until the start of odd turns (1, 3, 5...); other skills keep normal timing",
            ),
            (
                self.var_guild_raid_skills_max,
                "Guild Raid Skills Maxed (1M / 100%)",
                "Maxes Guild Shelling (1M boss dmg), Absolute Protection (100% 1-hit DR + 100% HP), and Combat Support (100% HP/MP + 20 debuffs dispelled)",
            ),
            (
                self.var_guild_raid_boss_no_counter,
                "Guild Raid Boss 0% Counter Rate",
                "Sets all Guild Raid boss counterattack rates to 0% instead of 300 (3%)",
            ),
            (self.var_single_black_hammer, "Single Black Hammer (+16..+26)", "Uses one black hammer per transcendence attempt instead of scaling 1, 2, 3..."),
            (self.var_equipment_tier_upgrades, "One Hammer per Equipment Tier", "One hammer advances equipment to +15, +20 or +26, depending on its current tier"),
            (self.var_single_gem_fang, "Single Dragon Fang Opens All 3 Gem Slots", "Uses one Dragon Fang to open all 3 gem slots on an equipment at once while keeping existing gems (also relaxes the client-side 2/3-fang inventory gate)"),
            (self.var_upgrade_no_fail_above_20, "No Upgrade Failure Above +20", "Makes +21..+26 equipment upgrades always succeed, so no insurance card is needed"),
            (self.var_battle_arena_save_fix, "Battle Arena Save Button (Client Hook)", "Client runtime hook applied after the AppSealing/covault finalization; makes the Battle Arena team Save button work"),
            (self.var_sacred_lands_restore, "Restore Sacred Lands Set", "Fixes the Sacred Lands (Support, slot IV) client grade and adds it back to the ★4 set selection tickets and rotation"),
            (self.var_coocoo_exp_x2, "Coocoo EXP x2 Always", "Always applies the x2 EXP bonus when leveling heroes with coocoo experience items"),
            (self.var_coocoo_level_x2, "Coocoo Level x2", "Doubles the coocoo levels dropped by all 30 Coocoo Garden / Pit of Nephthys stages (final stage 220 -> 440)"),
            (self.var_ship_parts_90_off, "90% Off Battleship Parts (Unknown Paradise)", "Applies a 90% discount to every battleship part gold upgrade in Unknown Paradise"),
            (self.var_crystal_skill_90_off, "90% Off Core Crystal Upgrades (Unknown Paradise)", "Reduces the three crystal skill upgrade costs from 50 to 5 Kraken Scales each"),
            (self.var_gem_mining_x10, "Gems x10 (Mining)", "Gem-mining rolls award 10 gems of the same type instead of 1, including the 20-crystal paid roll"),
            (self.var_gem_mining_types, "Gem Type Restriction", "Restricts gem-mining rolls to MP, Counter Rate, Counter Damage, Dodge and Hit Rate (excludes HP/ATK/DEF/CRIT sold in the Special Beginner Package)"),
            (self.var_gem_level6, "Gems Level 6", "Gems obtained or bought in the lobby gem screen are level 6 instead of level 1 (same attribute)"),
            (self.var_gem_upgrade_gold_half, "50% Off Gem Upgrade Gold", "Halves the gold fee charged by lobby gem upgrades while keeping the duplicate/consumable cost unchanged"),
            (self.var_stamina_cost_half, "50% Dungeon Stamina Cost (default)", "Server-side half debit used by --all; the client may still display/validate the full cost"),
            (self.var_stamina_potion_1000, "Stamina Potion Restores 1000", "Makes normal Stamina Potions restore 1000 points instead of the current max stamina"),
            (self.var_align_16k, "Android 16 / 16 KB Page Alignment", "Aligns shared libraries to 16 KB boundaries for HyperOS / Android 16"),
        ]

        options_container = tk.Frame(card, bg=BG_CARD)
        options_container.pack(fill="both", expand=True)

        canvas = tk.Canvas(options_container, bg=BG_CARD, highlightthickness=0, height=270)
        scrollbar = tk.Scrollbar(options_container, orient="vertical", command=canvas.yview)
        grid_frame = tk.Frame(canvas, bg=BG_CARD)
        self._feature_canvas = canvas
        self._feature_grid_frame = grid_frame
        description_labels: list[tk.Label] = []

        grid_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all")),
        )
        canvas_window = canvas.create_window((0, 0), window=grid_frame, anchor="nw")

        def _on_canvas_configure(event):
            canvas.itemconfig(canvas_window, width=event.width)
            for label in description_labels:
                label.configure(wraplength=max(180, event.width - 38))

        canvas.bind("<Configure>", _on_canvas_configure)
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        def _scroll_if_hovered(event: Any, units: int) -> None:
            w = canvas.winfo_containing(event.x_root, event.y_root)
            if w is not None and (w == canvas or str(w).startswith(str(grid_frame))):
                canvas.yview_scroll(units, "units")

        def _on_mousewheel(event: Any) -> None:
            delta = event.delta
            step = (
                int(-delta / 120)
                if abs(delta) >= 120
                else (-1 if delta > 0 else 1)
            )
            _scroll_if_hovered(event, step)

        self.bind_all("<MouseWheel>", _on_mousewheel, add="+")
        # X11 sends Button-4/5 instead of MouseWheel.
        self.bind_all(
            "<Button-4>",
            lambda event: _scroll_if_hovered(event, -3),
            add="+",
        )
        self.bind_all(
            "<Button-5>",
            lambda event: _scroll_if_hovered(event, 3),
            add="+",
        )

        options_by_var = {id(var): (var, title, desc) for var, title, desc in options}
        catalog_vars = [
            getattr(self, feature.variable)
            for group in FEATURE_GROUPS
            for feature in group.features
            if feature.variable is not None
        ]
        if (len(options_by_var) != len(options) or len(catalog_vars) != len(options)
                or {id(var) for var in catalog_vars} != options_by_var.keys()):
            raise ValueError("GUI feature catalog and option controls do not match")

        for group in FEATURE_GROUPS:
            tk.Label(
                grid_frame,
                text=f"{group.number}  {group.title}",
                font=(FONT_FAMILY, 9, "bold"),
                bg=BG_CARD,
                fg=ACCENT_CYAN,
                anchor="w",
            ).pack(fill="x", pady=(8, 2))
            for feature in group.features:
                if feature.field in {"lan_redirect", "allow_unknown"}:
                    continue  # Network and input-guard controls are rendered separately.
                row = tk.Frame(grid_frame, bg=BG_CARD)
                row.pack(fill="x", padx=(10, 0), pady=2)
                if feature.variable is None:
                    tk.Label(
                        row, text=f"{feature.number}  {feature.name} (always on)",
                        font=(FONT_FAMILY, 9, "bold"), bg=BG_CARD,
                        fg=TEXT_SECONDARY, anchor="w",
                    ).pack(fill="x")
                    continue
                var, title, desc = options_by_var[id(getattr(self, feature.variable))]
                chk = tk.Checkbutton(
                    row,
                    text=f"{feature.number}  {title}",
                    variable=var,
                    font=(FONT_FAMILY, 9, "bold"),
                    bg=BG_CARD,
                    fg=TEXT_PRIMARY,
                    selectcolor=BG_INPUT,
                    activebackground=BG_CARD,
                    activeforeground=ACCENT_CYAN,
                    anchor="w",
                    justify="left",
                    wraplength=300,
                )
                chk.pack(fill="x")
                self._numbered_checkbuttons.append(chk)
                lbl_desc = tk.Label(
                    row, text=desc, font=(FONT_FAMILY, 8), bg=BG_CARD,
                    fg=TEXT_MUTED, anchor="w", justify="left", wraplength=300,
                )
                lbl_desc.pack(fill="x", padx=(23, 0))
                description_labels.append(lbl_desc)

        # Network Mode Selection
        net_frame = tk.Frame(card, bg=BG_CARD)
        net_frame.pack(fill="x", pady=(8, 0))

        tk.Label(
            net_frame,
            text=f"{feature_by_field('lan_redirect').number}  Network Target Mode:",
            font=(FONT_FAMILY, 9, "bold"),
            bg=BG_CARD,
            fg=TEXT_SECONDARY,
        ).pack(anchor="w", pady=(0, 2))

        net_choices = tk.Frame(net_frame, bg=BG_CARD)
        net_choices.pack(fill="x")

        self.net_mode_var = tk.StringVar(value="offline")
        rb_off = tk.Radiobutton(
            net_choices,
            text="Offline Standalone (Default)",
            variable=self.net_mode_var,
            value="offline",
            font=(FONT_FAMILY, 9),
            bg=BG_CARD,
            fg=TEXT_PRIMARY,
            selectcolor=BG_INPUT,
            activebackground=BG_CARD,
            command=self._on_net_mode_changed,
        )
        rb_off.pack(anchor="w", padx=4)

        rb_lan = tk.Radiobutton(
            net_choices,
            text="Redirect to LAN Server",
            variable=self.net_mode_var,
            value="lan",
            font=(FONT_FAMILY, 9),
            bg=BG_CARD,
            fg=TEXT_PRIMARY,
            selectcolor=BG_INPUT,
            activebackground=BG_CARD,
            command=self._on_net_mode_changed,
        )
        rb_lan.pack(anchor="w", padx=4)

        # LAN Server endpoint inputs
        self.lan_input_frame = tk.Frame(card, bg=BG_CARD)
        self.var_lan_ip = tk.StringVar(value=os.environ.get("FWT_LAN_SERVER", ""))
        self.var_lan_port = tk.StringVar(value="8010")

        tk.Label(
            self.lan_input_frame,
            text="LAN Server IP:",
            font=(FONT_FAMILY, 8),
            bg=BG_CARD,
            fg=TEXT_SECONDARY,
        ).pack(side="left", padx=(16, 4))
        self.entry_lan_ip = tk.Entry(
            self.lan_input_frame,
            textvariable=self.var_lan_ip,
            font=(FONT_MONO, 8),
            bg=BG_INPUT,
            fg=TEXT_PRIMARY,
            width=15,
        )
        self.entry_lan_ip.pack(side="left", padx=2)

        tk.Label(
            self.lan_input_frame,
            text="Port:",
            font=(FONT_FAMILY, 8),
            bg=BG_CARD,
            fg=TEXT_SECONDARY,
        ).pack(side="left", padx=(8, 4))
        self.entry_lan_port = tk.Entry(
            self.lan_input_frame,
            textvariable=self.var_lan_port,
            font=(FONT_MONO, 8),
            bg=BG_INPUT,
            fg=TEXT_PRIMARY,
            width=6,
        )
        self.entry_lan_port.pack(side="left", padx=2)

    def _on_net_mode_changed(self):
        if self.net_mode_var.get() == "lan":
            self.lan_input_frame.pack(fill="x", pady=4)
        else:
            self.lan_input_frame.pack_forget()

    def _build_dev_section(self, parent: tk.Widget):
        """Development card: reverse-engineering instrumentation.

        Everything here lands behind the master switch and forces the output to
        a ``*-dev.apk`` name, so a dev build can never be mistaken for a release
        artifact (``tools/create_distribution_zip.py`` refuses them too).
        """
        card = tk.LabelFrame(
            parent,
            text=" 3. Development — dev build (never distribute) ",
            font=(FONT_FAMILY, 10, "bold"),
            bg=BG_CARD,
            fg=ACCENT_AMBER,
            bd=1,
            relief="solid",
            padx=PAD_MD,
            pady=PAD_SM,
        )
        card.pack(fill="x", pady=(0, PAD_SM))

        self.var_dev_enabled = tk.BooleanVar(value=False)
        self.var_dev_debuggable = tk.BooleanVar(value=False)
        self.var_dev_keep_version = tk.BooleanVar(value=False)
        self.var_dev_log = tk.BooleanVar(value=False)
        self.var_dev_log_limit = tk.StringVar(value="1024")
        self.var_dev_log_commands = tk.StringVar(value="")
        self.var_dev_counters = tk.BooleanVar(value=False)
        self.var_dev_marker = tk.BooleanVar(value=False)
        self.var_dev_log_response = tk.BooleanVar(value=False)
        self.var_dev_timing = tk.BooleanVar(value=False)
        self.var_dev_snapshots = tk.BooleanVar(value=False)
        self.var_dev_endpoint = tk.BooleanVar(value=False)
        self.var_lab_traps = tk.BooleanVar(value=False)

        self.chk_dev_enabled = tk.Checkbutton(
            card,
            text=f"{feature_by_field('dev.enabled').number}  Enable dev instrumentation (output forced to *-dev.apk)",
            variable=self.var_dev_enabled,
            command=self._sync_dev_state,
            font=(FONT_FAMILY, 9, "bold"),
            bg=BG_CARD,
            fg=ACCENT_AMBER,
            selectcolor=BG_INPUT,
            activebackground=BG_CARD,
            activeforeground=ACCENT_AMBER,
            justify="left",
            wraplength=300,
        )
        self.chk_dev_enabled.pack(anchor="w")
        self._numbered_checkbuttons.append(self.chk_dev_enabled)

        tk.Label(
            card,
            text=(
                "Features are wired one phase at a time; anything requested but not "
                "implemented yet is reported in the log and leaves the binary untouched."
            ),
            font=(FONT_FAMILY, 8),
            bg=BG_CARD,
            fg=TEXT_MUTED,
            justify="left",
            wraplength=520,
        ).pack(anchor="w", pady=(2, 4))

        self._dev_toggle_widgets: list[tk.Widget] = []

        def _group(title: str, entries, fg: str = ACCENT_CYAN) -> None:
            frame = tk.LabelFrame(
                card,
                text=f" {title} ",
                font=(FONT_FAMILY, 8, "bold"),
                bg=BG_CARD,
                fg=fg,
                bd=1,
                relief="groove",
                padx=PAD_SM,
                pady=2,
            )
            frame.pack(fill="x", pady=(0, 2))
            for var, field_name, label in entries:
                chk = tk.Checkbutton(
                    frame,
                    text=f"{feature_by_field(field_name).number}  {label}",
                    variable=var,
                    font=(FONT_FAMILY, 8),
                    bg=BG_CARD,
                    fg=TEXT_SECONDARY,
                    selectcolor=BG_INPUT,
                    activebackground=BG_CARD,
                    activeforeground=TEXT_SECONDARY,
                    justify="left",
                    wraplength=300,
                )
                chk.pack(anchor="w")
                self._dev_toggle_widgets.append(chk)
                self._numbered_checkbuttons.append(chk)

        _group(
            f"{DEV_GROUPS[0].number}  {DEV_GROUPS[0].title}",
            (
                (self.var_dev_log, "dev.log_dispatch", "Dispatch log to logcat (request/response, truncated)"),
                (self.var_dev_counters, "dev.hit_counters", "Per-patch hit counters"),
                (self.var_dev_timing, "dev.handler_timing", "Handler timing (cntvct_el0)"),
            ),
        )
        _group(
            f"{DEV_GROUPS[1].number}  {DEV_GROUPS[1].title}",
            (
                (self.var_dev_debuggable, "dev.debuggable", "debuggable=true (run-as / backup without root)"),
                (
                    self.var_dev_keep_version,
                    "dev.keep_version",
                    "Keep versionName (no '-dev' suffix; use when the game validates it)",
                ),
                (self.var_dev_marker, "dev.build_marker", "Build marker logged at boot"),
                (self.var_dev_log_response, "dev.log_responses", "Log response bodies (pairs with the request)"),
                (self.var_dev_endpoint, "dev.dev_endpoint", "DEV_DUMP endpoint on the embedded server"),
            ),
        )

        tune = tk.Frame(card, bg=BG_CARD)
        tune.pack(fill="x", pady=(2, 0))
        limit_row = tk.Frame(tune, bg=BG_CARD)
        limit_row.pack(fill="x")
        tk.Label(
            limit_row,
            text=f"{feature_by_field('dev.log_body_limit').number}  Log limit (bytes):",
            font=(FONT_FAMILY, 8),
            bg=BG_CARD,
            fg=TEXT_SECONDARY,
        ).pack(side="left")
        ent_limit = tk.Entry(
            limit_row,
            textvariable=self.var_dev_log_limit,
            width=7,
            font=(FONT_FAMILY, 8),
            bg=BG_INPUT,
            fg=TEXT_PRIMARY,
            insertbackground=TEXT_PRIMARY,
        )
        ent_limit.pack(side="left", padx=(4, 12))
        commands_row = tk.Frame(tune, bg=BG_CARD)
        commands_row.pack(fill="x")
        tk.Label(
            commands_row,
            text=f"{feature_by_field('dev.log_commands').number}  Commands (CSV, offline filter):",
            font=(FONT_FAMILY, 8),
            bg=BG_CARD,
            fg=TEXT_SECONDARY,
        ).pack(side="left")
        ent_cmds = tk.Entry(
            commands_row,
            textvariable=self.var_dev_log_commands,
            width=26,
            font=(FONT_FAMILY, 8),
            bg=BG_INPUT,
            fg=TEXT_PRIMARY,
            insertbackground=TEXT_PRIMARY,
        )
        ent_cmds.pack(side="left", padx=(4, 0))
        self._dev_toggle_widgets.extend((ent_limit, ent_cmds))

        _group(
            f"{DEV_GROUPS[2].number}  {DEV_GROUPS[2].title}",
            (
                (self.var_dev_snapshots, "dev.state_snapshots", "Numbered state snapshots (pending)"),
                (self.var_lab_traps, "dev.lab_traps", "brk #0 dead-code traps / AppSealing experiments (pending)"),
            ),
            fg=ACCENT_AMBER,
        )

        self._sync_dev_state()

    def _sync_dev_state(self) -> None:
        """Enables/disables the dev toggles and keeps the output name in sync."""
        enabled = self.var_dev_enabled.get()
        state = "normal" if enabled else "disabled"
        for widget in getattr(self, "_dev_toggle_widgets", []):
            widget.config(state=state)
        if hasattr(self, "lbl_dev_badge"):
            self.lbl_dev_badge.config(text="● DEV BUILD" if enabled else "")
        if hasattr(self, "out_picker"):
            path = self.out_picker.get_path().strip()
            if path.lower().endswith(".apk"):
                candidate = Path(path)
                if enabled and not is_dev_output_path(candidate):
                    stem = candidate.stem.removesuffix("-release")
                    self.out_picker.var.set(
                        str(
                            candidate.with_name(
                                f"{stem}{DEV_OUTPUT_SUFFIX}{candidate.suffix}"
                            )
                        )
                    )
                elif not enabled and is_dev_output_path(candidate):
                    stem = candidate.stem[: -len(DEV_OUTPUT_SUFFIX)]
                    self.out_picker.var.set(
                        str(candidate.with_name(f"{stem}-release{candidate.suffix}"))
                    )

    def _build_adb_section(self, parent: tk.Widget):
        card = tk.LabelFrame(
            parent,
            text=" 4. Device & Savegame Management (ADB) ",
            font=(FONT_FAMILY, 10, "bold"),
            bg=BG_CARD,
            fg=ACCENT_CYAN,
            bd=1,
            relief="solid",
            padx=PAD_MD,
            pady=PAD_SM,
        )
        card.pack(fill="x", pady=(0, PAD_SM))

        row1 = tk.Frame(card, bg=BG_CARD)
        row1.pack(fill="x", pady=2)

        tk.Label(
            row1,
            text="Target Device:",
            font=(FONT_FAMILY, 9, "bold"),
            bg=BG_CARD,
            fg=TEXT_SECONDARY,
        ).pack(side="left", padx=(0, 6))

        self.device_combo_var = tk.StringVar()
        self.device_combo = ttk.Combobox(
            row1,
            textvariable=self.device_combo_var,
            state="readonly",
            width=28,
        )
        self.device_combo.pack(side="left", padx=(0, 6))

        self.btn_refresh = tk.Button(
            row1,
            text="🔄 Refresh",
            command=self.refresh_devices,
            font=(FONT_FAMILY, 8),
            bg=BG_BORDER,
            fg=TEXT_PRIMARY,
            bd=0,
            padx=8,
            pady=2,
            cursor="hand2",
        )
        self.btn_refresh.pack(side="left", padx=2)

        self.btn_connect = tk.Button(
            row1,
            text="📶 Connect IP",
            command=self.connect_wifi_adb,
            font=(FONT_FAMILY, 8),
            bg=BG_BORDER,
            fg=TEXT_PRIMARY,
            bd=0,
            padx=8,
            pady=2,
            cursor="hand2",
        )
        self.btn_connect.pack(side="left", padx=2)

        # Save Backup controls
        row2 = tk.Frame(card, bg=BG_CARD)
        row2.pack(fill="x", pady=(6, 2))

        self.btn_backup = tk.Button(
            row2,
            text="💾 Backup Device Save Now",
            command=self.backup_device_save,
            font=(FONT_FAMILY, 9, "bold"),
            bg=ACCENT_PURPLE,
            fg="#ffffff",
            activebackground="#7c3aed",
            activeforeground="#ffffff",
            bd=0,
            padx=10,
            pady=3,
            cursor="hand2",
        )
        self.btn_backup.pack(side="left", padx=(0, PAD_MD))

        self.var_autobackup = tk.BooleanVar(value=True)
        chk_autobackup = tk.Checkbutton(
            row2,
            text="Auto-backup save before installing",
            variable=self.var_autobackup,
            font=(FONT_FAMILY, 8),
            bg=BG_CARD,
            fg=TEXT_SECONDARY,
            selectcolor=BG_INPUT,
            activebackground=BG_CARD,
            activeforeground=TEXT_PRIMARY,
        )
        chk_autobackup.pack(side="left")

        row3 = tk.Frame(card, bg=BG_CARD)
        row3.pack(fill="x", pady=(4, 2))

        self.btn_restore = tk.Button(
            row3,
            text="♻ Restore Save JSON...",
            command=self.restore_device_save,
            font=(FONT_FAMILY, 8),
            bg=BG_BORDER,
            fg=TEXT_PRIMARY,
            bd=0,
            padx=8,
            pady=2,
            cursor="hand2",
        )
        self.btn_restore.pack(side="left", padx=(0, PAD_SM))

        self.btn_uninstall = tk.Button(
            row3,
            text="🗑 Uninstall App (wipes data)",
            command=self.uninstall_app,
            font=(FONT_FAMILY, 8),
            bg=BG_BORDER,
            fg=ACCENT_RED,
            bd=0,
            padx=8,
            pady=2,
            cursor="hand2",
        )
        self.btn_uninstall.pack(side="left")

    def _build_actions_section(self, parent: tk.Widget):
        card = tk.Frame(parent, bg=BG_MAIN)
        card.pack(fill="x", pady=PAD_SM)

        self.btn_generate = tk.Button(
            card,
            text="📦 Generate Patched APK Only",
            command=lambda: self.run_build(install_after=False),
            font=(FONT_FAMILY, 10, "bold"),
            bg=BG_BORDER,
            fg=TEXT_PRIMARY,
            activebackground=BG_INPUT,
            activeforeground=TEXT_PRIMARY,
            bd=0,
            padx=14,
            pady=8,
            cursor="hand2",
        )
        self.btn_generate.pack(side="left", fill="x", expand=True, padx=(0, 4))

        self.btn_install = tk.Button(
            card,
            text="🚀 Generate & Install via ADB",
            command=lambda: self.run_build(install_after=True),
            font=(FONT_FAMILY, 10, "bold"),
            bg=ACCENT_GREEN,
            fg="#ffffff",
            activebackground=ACCENT_GREEN_HOVER,
            activeforeground="#ffffff",
            bd=0,
            padx=14,
            pady=8,
            cursor="hand2",
        )
        self.btn_install.pack(side="right", fill="x", expand=True, padx=(4, 0))

        self.btn_cancel = tk.Button(
            card,
            text="✖ Cancel",
            command=self.cancel_build,
            font=(FONT_FAMILY, 9, "bold"),
            bg=ACCENT_RED,
            fg="#ffffff",
            activebackground="#b91c1c",
            activeforeground="#ffffff",
            bd=0,
            padx=10,
            pady=8,
            cursor="hand2",
            state="disabled",
        )
        self.btn_cancel.pack(side="right", padx=(4, 0))

    def _build_footer(self):
        footer = tk.Frame(self, bg=BG_CARD, bd=1, relief="solid")
        footer.pack(fill="x", padx=PAD_MD, pady=(PAD_SM, PAD_MD))

        self.lbl_footer = tk.Label(
            footer,
            text="Ready. Select base APK and custom features, then click Generate.",
            font=(FONT_FAMILY, 8),
            bg=BG_CARD,
            fg=TEXT_MUTED,
            padx=8,
            pady=4,
        )
        self.lbl_footer.pack(side="left")

    # -----------------------------------------------------------------------
    # Background Logic & Handlers
    # -----------------------------------------------------------------------
    def _initial_checks(self):
        self.log_viewer.log("FWT Reborn Client Patcher initialized.")
        self.log_viewer.log(f"Project directory: {self.project_root}")

        # Check Tools
        if self.tools.has_packaging_tools:
            self.badge_tools.set_status("Tools: Ready", active=True)
            zipalign_name = Path(self.tools.zipalign).name if self.tools.zipalign else "?"
            apksigner_name = (
                Path(self.tools.apksigner).name if self.tools.apksigner else "?"
            )
            self.log_viewer.log(
                f"Build tools detected: zipalign={zipalign_name}, "
                f"apksigner={apksigner_name}"
            )
        else:
            self.badge_tools.set_status("Tools: Missing", active=False, color=ACCENT_RED)
            self.log_viewer.log("Warning: Android build tools (zipalign/apksigner/keytool) not fully found.", "warn")

        # Discover devices only if ADB exists
        if self.tools.has_adb:
            self.refresh_devices()
        else:
            self.badge_adb.set_status("ADB: Not Found", active=False, color=ACCENT_RED)
            self.log_viewer.log(
                "ADB executable not found; install Android platform-tools or set ANDROID_HOME.",
                "warn",
            )

        # Auto-inspect base APK if present
        if self.default_source.is_file():
            self.inspect_base_apk()

    def refresh_devices(self):
        def _task():
            try:
                devs = self.adb.list_devices()
                self.devices = devs
            except Exception as exc:
                self.log_viewer.log(f"Device discovery failed: {exc}", "error")
                self.post_ui(
                    lambda: self.badge_adb.set_status(
                        "ADB: Error", active=False, color=ACCENT_RED
                    )
                )
                return

            def _update_ui():
                if devs:
                    self.badge_adb.set_status(f"ADB: {len(devs)} Device(s)", active=True)
                    labels = [d["label"] for d in devs]
                    self.device_combo["values"] = labels
                    if not self.device_combo_var.get() or self.device_combo_var.get() not in labels:
                        self.device_combo_var.set(labels[0])
                    self.log_viewer.log(f"Discovered {len(devs)} ADB device(s): {', '.join(labels)}", "info")
                else:
                    self.badge_adb.set_status("ADB: No Devices", active=False)
                    self.device_combo["values"] = []
                    self.device_combo_var.set("")
                    self.log_viewer.log("No ADB devices connected. Click 'Connect IP' for Wi-Fi ADB.", "dim")

            self.post_ui(_update_ui)

        threading.Thread(target=_task, daemon=True).start()

    def connect_wifi_adb(self):
        ip_port = simpledialog.askstring(
            "Connect Wi-Fi ADB",
            "Enter Device IP:Port (e.g. 192.0.2.10:5555):",
            parent=self,
        )
        if not ip_port:
            return

        def _task():
            self.log_viewer.log(f"Connecting to ADB target: {ip_port}...")
            ok, msg = self.adb.connect(ip_port)
            if ok:
                self.log_viewer.log(f"Connected: {msg}", "success")
                self.refresh_devices()
            else:
                self.log_viewer.log(f"Connection failed: {msg}", "error")
                self.post_ui(messagebox.showerror, "Connection Failed", msg)

        threading.Thread(target=_task, daemon=True).start()

    def _get_selected_device_id(self) -> Optional[str]:
        val = self.device_combo_var.get()
        if not val:
            return None
        return val.split()[0]

    def _begin_device_op(self) -> bool:
        if self.is_busy or self.device_op_active:
            messagebox.showwarning(
                "Busy", "Another build or device operation is already running."
            )
            return False
        self.device_op_active = True
        return True

    def _end_device_op(self) -> None:
        self.device_op_active = False

    def backup_device_save(self):
        dev_id = self._get_selected_device_id()
        if not dev_id:
            messagebox.showwarning("No Device", "Please select a connected ADB device first.")
            return
        if not self._begin_device_op():
            return

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = self.backups_dir / f"fwt_server_state_v1_{ts}.json"

        def _task():
            try:
                self.log_viewer.log(f"Backing up savegame from device {dev_id}...")
                ok, msg = self.adb.backup_save(dev_id, backup_file)
                if ok:
                    self.log_viewer.log(f"Savegame backup created: {backup_file.name} ({msg})", "success")
                    self.post_ui(
                        messagebox.showinfo,
                        "Backup Successful",
                        f"Savegame safely backed up to:\n{backup_file}",
                    )
                else:
                    self.log_viewer.log(f"Backup failed: {msg}", "error")
                    self.post_ui(messagebox.showerror, "Backup Failed", msg)
            finally:
                self.post_ui(self._end_device_op)

        threading.Thread(target=_task, daemon=True).start()

    def restore_device_save(self):
        dev_id = self._get_selected_device_id()
        if not dev_id:
            messagebox.showwarning("No Device", "Please select a connected ADB device first.")
            return
        backup_file = filedialog.askopenfilename(
            title="Select savegame JSON",
            filetypes=[("JSON save", "*.json"), ("All Files", "*.*")],
            initialdir=str(self.backups_dir),
        )
        if not backup_file:
            return
        if not messagebox.askyesno(
            "Restore Save",
            "Restoring writes to app-private storage and requires root.\n"
            "The app must be installed. Continue?",
        ):
            return
        if not self._begin_device_op():
            return

        def _task():
            try:
                self.log_viewer.log(f"Restoring save to {dev_id}...")
                ok, msg = self.adb.restore_save(dev_id, Path(backup_file))
                if ok:
                    self.log_viewer.log(f"Restore successful: {msg}", "success")
                    self.post_ui(messagebox.showinfo, "Restore Successful", msg)
                else:
                    self.log_viewer.log(f"Restore failed: {msg}", "error")
                    self.post_ui(messagebox.showerror, "Restore Failed", msg)
            finally:
                self.post_ui(self._end_device_op)

        threading.Thread(target=_task, daemon=True).start()

    def uninstall_app(self):
        dev_id = self._get_selected_device_id()
        if not dev_id:
            messagebox.showwarning("No Device", "Please select a connected ADB device first.")
            return
        if not messagebox.askyesno(
            "Uninstall App",
            "This deletes com.nexon.fwar and ALL app data, including the save.\n"
            "Back up the save first! Continue?",
            icon="warning",
        ):
            return
        if not self._begin_device_op():
            return

        def _task():
            try:
                self.log_viewer.log(f"Uninstalling com.nexon.fwar from {dev_id}...")
                ok, msg = self.adb.uninstall_apk(dev_id)
                if ok:
                    self.log_viewer.log(f"Uninstall successful: {msg}", "success")
                    self.post_ui(messagebox.showinfo, "Uninstall Successful", msg)
                    self.refresh_devices()
                else:
                    self.log_viewer.log(f"Uninstall failed: {msg}", "error")
                    self.post_ui(messagebox.showerror, "Uninstall Failed", msg)
            finally:
                self.post_ui(self._end_device_op)

        threading.Thread(target=_task, daemon=True).start()

    def inspect_base_apk(self):
        apk_path = Path(self.in_picker.get_path())
        if not apk_path.is_file():
            messagebox.showwarning("File Missing", f"Base APK file not found:\n{apk_path}")
            return

        self.lbl_inspection_status.config(text="Inspecting APK...", fg=ACCENT_CYAN)

        def _task():
            self.log_viewer.log(f"Inspecting {apk_path.name}...")
            try:
                rep = inspect_apk(apk_path)
            except Exception as exc:
                self.log_viewer.log(f"Inspection failed: {exc}", "error")
                self.post_ui(
                    self.lbl_inspection_status.config,
                    text="Inspection failed",
                    fg=ACCENT_RED,
                )
                return

            def _update_ui():
                if not rep.is_valid_apk:
                    self.lbl_inspection_status.config(text="Invalid APK file", fg=ACCENT_RED)
                    self.log_viewer.log(
                        f"Inspection error: {rep.error_message or rep.alignment_details}",
                        "error",
                    )
                    return

                active_features = [f.name for f in rep.features.values() if f.active]
                if rep.is_pristine_reference and rep.is_pristine_dex:
                    summary = "Pristine Original 0.682 APK (Clean Reference Core)"
                    color = ACCENT_GREEN
                elif active_features:
                    summary = f"Custom Patched APK ({len(active_features)} features active)"
                    color = ACCENT_CYAN
                else:
                    summary = "Unrecognized / Modified APK"
                    color = ACCENT_AMBER

                self.lbl_inspection_status.config(text=summary, fg=color)
                self.log_viewer.log(f"--- Inspection Report: {apk_path.name} ---", "bold")
                self.log_viewer.log(
                    f"Size: {rep.file_size_mb:.1f} MiB | Pristine SO: {rep.is_pristine_reference} "
                    f"| Pristine DEX: {rep.is_pristine_dex}"
                )
                self.log_viewer.log(f"SO SHA-256: {rep.so_sha256}")
                self.log_viewer.log(f"DEX SHA-256: {rep.dex_sha256}")
                self.log_viewer.log(
                    f"DEX Checksums: {rep.dex_checksum_valid} ({rep.dex_checksum_details})"
                )
                self.log_viewer.log(f"16 KB Alignment: {rep.alignment_16k} ({rep.alignment_details})")
                self.log_viewer.log(f"Signature: {rep.signature_details}")
                if rep.cave_overlap:
                    self.log_viewer.log(
                        "WARNING: legacy code-cave overlap detected (event coin vs. items).",
                        "warn",
                    )

                for feat in rep.features.values():
                    tag = "success" if feat.active else "dim"
                    self.log_viewer.log(f"  • {feat.name}: {feat.status} - {feat.details}", tag)
                self.log_viewer.log("--------------------------------------------------")

            self.post_ui(_update_ui)

        threading.Thread(target=_task, daemon=True).start()

    def _update_apk_info(self):
        p = self.in_picker.get_path()
        if p and Path(p).is_file():
            self.lbl_inspection_status.config(text="File selected. Click 'Inspect' to verify.", fg=TEXT_SECONDARY)

    def _poll_close_when_idle(self) -> None:
        if not self.is_busy and not bool(self.__dict__.get("device_op_active", False)):
            self.destroy()
            return
        self.after(200, self._poll_close_when_idle)

    def _on_close(self) -> None:
        """Refuses to kill a running build or ADB operation (subprocesses/temp files leak)."""
        device_busy = bool(self.__dict__.get("device_op_active", False))
        if not self.is_busy and not device_busy:
            self.destroy()
            return
        if bool(self.__dict__.get("_close_requested", False)):
            return
        if self.is_busy:
            title = "Build in progress"
            prompt = "A build is running. Cancel it and close when the current tool finishes?"
            log_msg = "Cancelling; the window will close after the current step."
        else:
            title = "Device operation in progress"
            prompt = "An ADB device operation is running. Wait for it to finish and then close?"
            log_msg = "Close requested; the window will close after the current device operation finishes."
        if not messagebox.askyesno(title, prompt, parent=self):
            return
        self._close_requested = True
        if self.is_busy:
            self._cancel_event.set()
            if hasattr(self, "btn_cancel"):
                self.btn_cancel.config(state="disabled")
        self.log_viewer.log(log_msg, "warn")
        self.after(200, self._poll_close_when_idle)

    def cancel_build(self):
        if not self.is_busy:
            return
        self._cancel_event.set()
        self.log_viewer.log(
            "Cancel requested; finishing the current external tool step...", "warn"
        )
        self.btn_cancel.config(state="disabled")

    def _collect_patch_options(
        self,
        *,
        lan_redirect: bool = False,
        server_ip: str = "127.0.0.1",
        server_port: int = 8010,
        allow_unknown: bool = False,
        dev_options: DevOptions | None = None,
    ) -> PatchOptions:
        """Assemble a ``PatchOptions`` instance from the current GUI variables."""
        return PatchOptions(
            campaign_gold=self.var_gold.get(),
            campaign_xp=self.var_xp.get(),
            no_equip_drops=self.var_no_equip_drops.get(),
            gene_priority=self.var_gene.get(),
            summon_rates=self.var_summon.get(),
            summon_rates_50_30_20=self.var_summon_50_30_20.get(),
            expedition_bonus=self.var_expedition.get(),
            english_localization=self.var_english.get(),
            event_discount=self.var_event_discount.get(),
            event_gene_unlimited=self.var_event_gene_unlimited.get(),
            event_limits_daily=self.var_event_limits_daily.get(),
            mythical_stone_shop=self.var_mythical_stone_shop.get(),
            hero_shop_offers=self.var_hero_shop_offers.get(),
            alex_awakening=self.var_alex_awakening.get(),
            alex_rebalance=self.var_alex_rebalance.get(),
            costume_packages_all=self.var_costume_packages_all.get(),
            recycle_six_star=self.var_recycle_six_star.get(),
            campaign_shop_discount=self.var_campaign_shop_discount.get(),
            mode_drops_x10=self.var_mode_drops_x10.get(),
            devil_boost_x10=self.var_devil_boost_x10.get(),
            battle_arena_fix=self.var_battle_arena_fix.get(),
            guild_raid_mercenary=self.var_guild_raid_mercenary.get(),
            guild_raid_reward_x10=self.var_guild_raid_reward_x10.get(),
            energy_flask_x10=self.var_energy_flask_x10.get(),
            option_max_attributes=self.var_option_max_attributes.get(),
            rune_box_random_type=self.var_rune_box_random_type.get(),
            rune_box_random_roll=self.var_rune_box_random_roll.get(),
            equipment_lock_fix=self.var_equipment_lock_fix.get(),
            equipment_single_mod_stone=self.var_equipment_single_mod_stone.get(),
            equipment_percent_options=self.var_equipment_percent_options.get(),
            equipment_upgrade_10_guarantee=(
                self.var_equipment_upgrade_10_guarantee.get()
            ),
            limit_break_cost_tenth=self.var_limit_break_cost_tenth.get(),
            limit_break_cost_fixed=self.var_limit_break_cost_fixed.get(),
            soulgear_enchant_always=self.var_soulgear_enchant_always.get(),
            rune_quality_factor=(10 if self.var_rune_quality_x10.get() else 0),
            rune_option_quality=self.var_rune_option_quality.get(),
            rune_upgrade_discount=self.var_rune_upgrade_discount.get(),
            gold_cylinder_x10=self.var_gold_cylinder_x10.get(),
            mana_cylinder_x10=self.var_mana_cylinder_x10.get(),
            event_coin_x10=self.var_event_coin_x10.get(),
            guild_raid_score_fix=self.var_guild_raid_score_fix.get(),
            guild_raid_fire_support=self.var_guild_raid_fire_support.get(),
            guild_raid_skills_max=self.var_guild_raid_skills_max.get(),
            guild_raid_boss_no_counter=self.var_guild_raid_boss_no_counter.get(),
            single_black_hammer=self.var_single_black_hammer.get(),
            equipment_tier_upgrades=self.var_equipment_tier_upgrades.get(),
            single_gem_fang=self.var_single_gem_fang.get(),
            upgrade_no_fail_above_20=self.var_upgrade_no_fail_above_20.get(),
            battle_arena_save_fix=self.var_battle_arena_save_fix.get(),
            sacred_lands_restore=self.var_sacred_lands_restore.get(),
            coocoo_exp_x2=self.var_coocoo_exp_x2.get(),
            coocoo_level_x2=self.var_coocoo_level_x2.get(),
            ship_parts_90_off=self.var_ship_parts_90_off.get(),
            crystal_skill_90_off=self.var_crystal_skill_90_off.get(),
            gem_mining_x10=self.var_gem_mining_x10.get(),
            gem_mining_types=self.var_gem_mining_types.get(),
            gem_level6=self.var_gem_level6.get(),
            gem_upgrade_gold_half=self.var_gem_upgrade_gold_half.get(),
            stamina_cost_half=self.var_stamina_cost_half.get(),
            stamina_potion_1000=self.var_stamina_potion_1000.get(),
            lan_redirect=lan_redirect,
            server_ip=server_ip,
            server_port=server_port,
            align_16k=self.var_align_16k.get(),
            allow_unknown=allow_unknown,
            dev=dev_options if dev_options is not None else DevOptions(),
        )

    def run_build(self, install_after: bool = False):
        if self.is_busy:
            return
        if self.device_op_active:
            messagebox.showwarning(
                "Device busy",
                "Wait for the current backup/restore/uninstall operation to finish.",
            )
            return

        input_text = self.in_picker.get_path().strip()
        output_text = self.out_picker.get_path().strip()
        if not input_text:
            messagebox.showerror("Error", "Please select the base APK.")
            return
        if not output_text:
            messagebox.showerror("Error", "Please select the output APK path.")
            return
        if not output_text.lower().endswith(".apk"):
            messagebox.showerror("Error", "The output file must have the .apk extension.")
            return
        in_apk = Path(input_text)
        out_apk = Path(output_text)
        if self.var_dev_enabled.get() and not is_dev_output_path(out_apk):
            suggested = out_apk.with_name(
                f"{out_apk.stem}{DEV_OUTPUT_SUFFIX}{out_apk.suffix}"
            )
            messagebox.showerror(
                "Dev build name",
                "A dev build must be written to a file ending in "
                f"'{DEV_OUTPUT_SUFFIX}.apk' so it can never be mistaken for a "
                f"release.\n\nUse: {suggested.name}",
            )
            return
        if not in_apk.is_file():
            messagebox.showerror("Error", f"Input APK file not found:\n{in_apk}")
            return
        if in_apk.resolve() == out_apk.resolve():
            messagebox.showerror(
                "Error", "Input and output APK paths are identical. Refusing to overwrite the base APK."
            )
            return

        dev_id = self._get_selected_device_id()
        if install_after and not dev_id:
            messagebox.showerror("Error", "No ADB device selected for installation.")
            return

        lan_redirect = self.net_mode_var.get() == "lan"
        server_ip = self.var_lan_ip.get().strip() or "127.0.0.1"
        try:
            server_port = int(self.var_lan_port.get().strip() or "8010")
        except ValueError:
            messagebox.showerror("Invalid LAN Port", "LAN port must be an integer between 1 and 65535.")
            return
        if not 1 <= server_port <= 65535:
            messagebox.showerror("Invalid LAN Port", "LAN port must be between 1 and 65535.")
            return
        if lan_redirect:
            try:
                ipaddress.IPv4Address(server_ip)
            except ValueError:
                messagebox.showerror("Invalid LAN IP", f"Invalid IPv4 address: {server_ip!r}")
                return

        force = self.var_force.get()
        if force and not messagebox.askyesno(
            "Advanced / Unsafe",
            "Patching a non-reference APK can corrupt the output.\n"
            "Use this only for development. Continue?",
            icon="warning",
        ):
            return

        try:
            dev_options = DevOptions(
                enabled=self.var_dev_enabled.get(),
                debuggable=self.var_dev_debuggable.get(),
                keep_version=self.var_dev_keep_version.get(),
                log_dispatch=self.var_dev_log.get(),
                log_body_limit=int(self.var_dev_log_limit.get().strip() or "0"),
                log_commands=self.var_dev_log_commands.get().strip(),
                hit_counters=self.var_dev_counters.get(),
                build_marker=self.var_dev_marker.get(),
                log_responses=self.var_dev_log_response.get(),
                handler_timing=self.var_dev_timing.get(),
                state_snapshots=self.var_dev_snapshots.get(),
                dev_endpoint=self.var_dev_endpoint.get(),
                lab_traps=self.var_lab_traps.get(),
            )
            dev_options.validate()
        except ValueError as exc:
            messagebox.showerror("Dev options", str(exc))
            return

        opts = self._collect_patch_options(
            lan_redirect=lan_redirect,
            server_ip=server_ip,
            server_port=server_port,
            allow_unknown=force,
            dev_options=dev_options,
        )
        try:
            validate_patch_options(opts)
        except ValueError as exc:
            messagebox.showerror("Invalid Patch Options", str(exc))
            return
        if not opts.has_selected_feature():
            messagebox.showwarning(
                "No Features Selected",
                "Select at least one patch feature or a development instrumentation flag.",
            )
            return
        autobackup = self.var_autobackup.get()
        self._cancel_event.clear()
        self._set_busy(True)

        def _task():
            try:
                # 1. Auto-backup save if requested. A failed backup aborts the
                # install: overwriting the app with a new signature can wipe data.
                if install_after and autobackup and dev_id:
                    state = self.adb.package_state(dev_id)
                    if state == "unknown":
                        self.log_viewer.log(
                            "Could not verify the installed package; aborting the "
                            "install instead of overwriting an unbacked-up save.",
                            "error",
                        )
                        self.post_ui(
                            messagebox.showerror,
                            "Install aborted",
                            "Could not determine whether the game is installed. "
                            "Reconnect the device and try again.",
                        )
                        return
                    if state == "not_installed":
                        self.log_viewer.log(
                            "Package is not installed yet; skipping pre-install save backup.",
                            "info",
                        )
                    else:
                        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                        backup_file = self.backups_dir / f"fwt_server_state_v1_{ts}.json"
                        self.log_viewer.log("Performing automatic save backup prior to install...")
                        ok, msg = self.adb.backup_save(dev_id, backup_file)
                        if not ok:
                            self.log_viewer.log(f"Auto-backup failed: {msg}", "error")
                            self.post_ui(
                                messagebox.showerror,
                                "Backup Failed — Install Aborted",
                                "The pre-install save backup failed, so installation was aborted.\n\n"
                                f"{msg}\n\n"
                                "Uncheck 'Auto-backup save before installing' only if you accept the risk.",
                            )
                            return
                        self.log_viewer.log(f"Auto-backup complete: {backup_file.name}", "success")

                # 2. Repack, align and sign
                self.log_viewer.log("Starting APK patch and repack process...", "bold")
                result = repack_and_sign_apk(
                    input_apk=in_apk,
                    output_apk=out_apk,
                    options=opts,
                    tools=self.tools,
                    keystore_path=self.keystore_path,
                    log_fn=lambda msg: self.log_viewer.log(msg),
                    cancel_event=self._cancel_event,
                )
                self.log_viewer.log(
                    "Patch counts: "
                    + ", ".join(f"{name}={count}" for name, count in result.counts.items()),
                    "info",
                )
                for warning in result.warnings:
                    self.log_viewer.log(f"WARNING: {warning}", "warn")

                # 3. Verify output against the requested feature set.
                self.log_viewer.log("Verifying generated APK...")
                out_rep = inspect_apk(out_apk)
                problems = verify_report(out_rep, opts)
                if problems:
                    for problem in problems:
                        self.log_viewer.log(f"Verification error: {problem}", "error")
                    self.post_ui(
                        messagebox.showerror,
                        "Verification Failed",
                        "The generated APK did not pass verification:\n\n"
                        + "\n".join(f"• {problem}" for problem in problems),
                    )
                    return

                active_count = sum(1 for f in out_rep.features.values() if f.active)
                self.log_viewer.log(
                    f"Verification passed: {active_count} active feature report(s), "
                    f"16KB={out_rep.alignment_16k}, signed={out_rep.is_signed}, "
                    f"DEX checksums={out_rep.dex_checksum_valid}",
                    "success",
                )

                # 4. Install via ADB if requested
                if install_after and dev_id:
                    self.log_viewer.log(f"Initiating ADB installation on {dev_id}...", "bold")
                    inst_ok, inst_msg = self.adb.install_apk(
                        dev_id,
                        out_apk,
                        log_fn=lambda msg: self.log_viewer.log(msg),
                    )
                    if inst_ok:
                        self.post_ui(
                            messagebox.showinfo,
                            "Success",
                            f"Patched APK successfully built and installed on {dev_id}!",
                        )
                    else:
                        self.post_ui(
                            messagebox.showerror,
                            "Install Failed",
                            f"Installation failed:\n{inst_msg}",
                        )
                else:
                    self.post_ui(
                        messagebox.showinfo,
                        "Success",
                        f"Patched APK successfully created at:\n{out_apk}",
                    )

            except Exception as exc:
                if "cancelled" in str(exc).lower():
                    self.log_viewer.log("Build cancelled by user.", "warn")
                    self.post_ui(
                        messagebox.showinfo,
                        "Cancelled",
                        "The build was cancelled. No output APK was replaced.",
                    )
                else:
                    self.log_viewer.log(f"Error during patch process: {exc}", "error")
                    self.post_ui(messagebox.showerror, "Error", f"Patching failed:\n{exc}")
            finally:
                self.post_ui(self._set_busy, False)

        threading.Thread(target=_task, daemon=True).start()

    def _set_busy(self, busy: bool):
        self.is_busy = busy
        state: Literal["disabled", "normal"] = "disabled" if busy else "normal"
        for widget in (
            self.btn_generate,
            self.btn_install,
            self.btn_inspect,
            self.btn_refresh,
            self.btn_connect,
            self.btn_backup,
            self.btn_restore,
            self.btn_uninstall,
        ):
            widget.config(state=state)
        self.btn_cancel.config(state="normal" if busy else "disabled")
        if busy:
            self.lbl_footer.config(text="Processing... Please wait (do not close the window).", fg=ACCENT_AMBER)
        else:
            self.lbl_footer.config(text="Ready.", fg=TEXT_MUTED)

