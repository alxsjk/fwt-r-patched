#!/usr/bin/env python3
"""FWT Reborn - Offline Client Patcher & Modding Suite.

Entry point supporting both Graphical Desktop App (Tkinter) and Headless CLI
for autonomous APK patching, feature injection, 16 KB alignment, signing,
and savegame backup/restore via ADB.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib.util
import ipaddress
import os
import sys
from dataclasses import fields
from datetime import datetime
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def _load_env_file() -> None:
    """Loads the local .env for CLI runs (not at import time).

    Importing this module from tests must not mutate os.environ with the
    developer's FWT_DEBUG/device/keystore settings.
    """
    try:
        from dotenv import load_dotenv

        load_dotenv(PROJECT_ROOT / ".env", override=False)
    except ImportError:
        pass

from core.apk_tooling import (
    AdbHelper,
    describe_missing_packaging_tools,
    locate_tools,
    repack_and_sign_apk,
)
from core.core_patches import DEV_OUTPUT_SUFFIX, DevOptions, PatchOptions, is_dev_output_path
from core.patch_inspector import (
    detect_cave_overlap,
    inspect_apk,
    inspect_native_so,
    verify_report,
)
from core.version import APP_NAME, APP_VERSION, versioned_output_path


def _configure_console() -> None:
    """Avoid UnicodeEncodeError on Windows cp1252 consoles (e.g. --help, ★)."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            with contextlib.suppress(AttributeError, ValueError):
                reconfigure(errors="replace")


def parse_lan_endpoint(value: str) -> tuple[str, int]:
    """Parses ``IP[:PORT]`` and validates it before any build starts."""
    cleaned = value.strip()
    if not cleaned:
        raise argparse.ArgumentTypeError("LAN endpoint cannot be empty")
    if ":" in cleaned:
        host, port_text = cleaned.rsplit(":", 1)
        try:
            port = int(port_text)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(f"invalid LAN port: {port_text!r}") from exc
    else:
        host, port = cleaned, 8010
    try:
        ipaddress.IPv4Address(host)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid IPv4 address: {host!r}") from exc
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError(f"LAN port out of range (1..65535): {port}")
    return host, port


def _cli_text(text: object) -> str:
    """ASCII-safe rendering for legacy Windows consoles."""
    return str(text).replace("★", "*").replace("…", "...")


def _backup_path() -> Path:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return PROJECT_ROOT / "backups" / f"fwt_server_state_v1_{ts}.json"


def _resolve_device(adb: AdbHelper, requested: str | None) -> tuple[str | None, str]:
    devices = adb.list_devices()
    if not devices:
        return None, "No ADB devices connected (check the USB cable or Wi-Fi ADB)."
    ready = [d for d in devices if d["state"] == "device"]
    if requested:
        if requested.startswith("-") or any(ch.isspace() for ch in requested):
            return None, f"Invalid device id {requested!r}."
        match = next((d for d in devices if d["id"] == requested), None)
        if match is None:
            known = ", ".join(f"{d['id']} ({d['state']})" for d in devices)
            return None, f"Device {requested!r} not found. Connected: {known}"
        if match["state"] != "device":
            return None, (
                f"Device {requested!r} is {match['state']}; accept the RSA prompt "
                "or reconnect it before installing."
            )
        return requested, ""
    if len(ready) == 1:
        return ready[0]["id"], ""
    if len(ready) > 1:
        known = ", ".join(d["id"] for d in ready)
        return None, f"Multiple devices connected ({known}); pass --device explicitly."
    known = ", ".join(f"{d['id']} ({d['state']})" for d in devices)
    return None, f"No ready ADB device. Connected: {known}"


def _print_inspection(rep, target_path: Path) -> None:
    print(f"\n--- Inspection Report: {target_path.name} ---")
    print(f"Size: {rep.file_size_mb:.1f} MiB")
    print(f"Reference SO Clean: {rep.is_pristine_reference}")
    print(f"Reference DEX Clean: {rep.is_pristine_dex}")
    print(f"SO SHA-256: {rep.so_sha256}")
    print(f"DEX SHA-256: {rep.dex_sha256}")
    print(f"DEX Checksums: {rep.dex_checksum_valid} ({_cli_text(rep.dex_checksum_details)})")
    print(f"16 KB Alignment: {rep.alignment_16k} ({_cli_text(rep.alignment_details)})")
    print(f"Signature: {_cli_text(rep.signature_details)}")
    print(f"Legacy cave overlap: {rep.cave_overlap}")
    print("\nFeatures:")
    for feat in rep.features.values():
        status_tag = "[ACTIVE]  " if feat.active else "[INACTIVE]"
        print(
            f"  {status_tag} {_cli_text(feat.name)}: "
            f"{_cli_text(feat.status)} ({_cli_text(feat.details)})"
        )
    print("--------------------------------------------------\n")


def _has_selected_feature(opts: PatchOptions) -> bool:
    """Return True if at least one patch feature or dev instrumentation flag is enabled."""
    return opts.has_selected_feature()


def run_cli(args: argparse.Namespace) -> int:
    tools = locate_tools()
    adb = AdbHelper(tools.adb)

    # 0. Toolchain preflight
    if args.check_tools:
        print("FWT Reborn tool check")
        print(f"  zipalign : {tools.zipalign or 'MISSING'}")
        print(f"  apksigner: {tools.apksigner or 'MISSING'}")
        print(f"  keytool  : {tools.keytool or 'MISSING'}")
        print(f"  adb      : {tools.adb or 'not found (optional for APK-only builds)'}")
        for module in ("dotenv", "UnityPy", "cryptography", "elftools", "capstone", "keystone"):
            state = "installed" if importlib.util.find_spec(module) else "MISSING"
            print(f"  python {module:<12}: {state}")
        if tools.has_packaging_tools:
            print("Packaging tools: READY")
            return 0
        print(describe_missing_packaging_tools(tools), file=sys.stderr)
        return 1

    # 1. Inspection mode
    if args.inspect:
        target_path = Path(args.inspect).expanduser()
        print(f"Inspecting APK: {target_path}...")
        rep = inspect_apk(target_path)
        if not rep.is_valid_apk:
            print(f"Error: {rep.error_message or rep.alignment_details}", file=sys.stderr)
            return 1
        _print_inspection(rep, target_path)
        return 0

    # 1b. Standalone .so inspection
    if args.inspect_so:
        target_path = Path(args.inspect_so).expanduser()
        if not target_path.is_file():
            print(f"Error: shared library not found at {target_path}", file=sys.stderr)
            return 1
        so_bytes = target_path.read_bytes()
        print(f"\n--- Native SO Report: {target_path.name} ---")
        print(f"Size: {len(so_bytes) / (1024 * 1024):.1f} MiB")
        print(f"SO SHA-256: {hashlib.sha256(so_bytes).hexdigest()}")
        print(f"Legacy cave overlap: {detect_cave_overlap(so_bytes)}")
        print("\nFeatures:")
        for feat in inspect_native_so(so_bytes).values():
            status_tag = "[ACTIVE]  " if feat.active else "[INACTIVE]"
            print(
                f"  {status_tag} {_cli_text(feat.name)}: "
                f"{_cli_text(feat.status)} ({_cli_text(feat.details)})"
            )
        print("--------------------------------------------------\n")
        return 0

    # 2. Save backup mode
    if args.backup:
        dev_id, error = _resolve_device(adb, args.device)
        if not dev_id:
            print(f"Error: {error}", file=sys.stderr)
            return 1
        backup_path = _backup_path()
        print(f"Backing up savegame from {dev_id} to {backup_path}...")
        ok, msg = adb.backup_save(dev_id, backup_path)
        if ok:
            print(f"Success: {msg}")
            return 0
        print(f"Error: {msg}", file=sys.stderr)
        return 1

    # 3. Restore mode (standalone)
    if args.restore and not args.install:
        dev_id, error = _resolve_device(adb, args.device)
        if not dev_id:
            print(f"Error: {error}", file=sys.stderr)
            return 1
        ok, msg = adb.restore_save(dev_id, Path(args.restore).expanduser())
        if ok:
            print(f"Success: {msg}")
            return 0
        print(f"Error: {msg}", file=sys.stderr)
        return 1

    # 4. Uninstall mode (standalone)
    if args.uninstall and not args.install:
        dev_id, error = _resolve_device(adb, args.device)
        if not dev_id:
            print(f"Error: {error}", file=sys.stderr)
            return 1
        ok, msg = adb.uninstall_apk(dev_id)
        if ok:
            print(f"Success: {msg}")
            return 0
        print(f"Error: {msg}", file=sys.stderr)
        return 1

    # 5. Patch & Build mode
    input_default = os.environ.get(
        "FWT_SOURCE_APK", "source/fwt_0.682_offline_v1574.apk"
    )
    output_default = os.environ.get("FWT_OUTPUT_APK") or "output/FWT-Reborn-Patched.apk"
    input_apk = (
        Path(args.input).expanduser()
        if args.input
        else (PROJECT_ROOT / input_default).expanduser()
    )
    output_apk = versioned_output_path(
        Path(args.output).expanduser()
        if args.output
        else (PROJECT_ROOT / output_default).expanduser(),
        dev=args.dev,
    )
    if output_apk.suffix.lower() != ".apk":
        print("Error: the output file must have the .apk extension.", file=sys.stderr)
        return 2

    if args.dev:
        if not is_dev_output_path(output_apk):
            suggested = output_apk.with_name(
                f"{output_apk.stem}{DEV_OUTPUT_SUFFIX}{output_apk.suffix}"
            )
            print(
                "Error: a dev build must be written to a '*"
                f"{DEV_OUTPUT_SUFFIX}.apk' file so it can never be mistaken for a "
                f"release. Try: {suggested}",
                file=sys.stderr,
            )
            return 2
        print(
            "*** DEV BUILD: reverse-engineering instrumentation enabled — "
            "do not distribute this APK ***"
        )
    if input_apk.resolve() == output_apk.resolve():
        print("Error: input and output APK paths are identical.", file=sys.stderr)
        return 1
    if not input_apk.is_file():
        print(f"Error: Input APK not found at {input_apk}", file=sys.stderr)
        return 1

    lan_redirect = args.lan is not None
    lan_ip, lan_port = args.lan if args.lan else ("127.0.0.1", 8010)

    if args.summon_rates and args.summon_50_30_20:
        print(
            "Error: --summon-rates (70/20/10) and --summon-50-30-20 (50/30/20) "
            "are mutually exclusive.",
            file=sys.stderr,
        )
        return 2

    # Classic summon profile handling.
    if args.summon_rates:
        summon_70_20_10 = True
        summon_50_30_20 = False
    elif args.summon_50_30_20 or args.all:
        summon_70_20_10 = False
        summon_50_30_20 = True
    else:
        summon_70_20_10 = False
        summon_50_30_20 = False

    # --all uses the server-side half debit.
    stamina_half = bool(args.stamina_cost_half or args.all)

    if args.limit_break_cost_tenth and args.limit_break_cost_fixed:
        print(
            "Error: --limit-break-cost-tenth and --limit-break-cost-fixed "
            "are mutually exclusive.",
            file=sys.stderr,
        )
        return 2

    # The 90% limit-break discount and the flat price are mutually exclusive;
    # --all ships the flat price unless --limit-break-cost-tenth is requested.
    limit_cost_tenth = bool(args.limit_break_cost_tenth)
    limit_cost_fixed = bool(args.limit_break_cost_fixed or (args.all and not limit_cost_tenth))

    try:
        dev_options = DevOptions(
            enabled=args.dev,
            debuggable=args.dev_debuggable,
            keep_version=args.dev_keep_version,
            log_dispatch=args.dev_log,
            log_body_limit=args.dev_log_limit,
            log_commands=args.dev_log_commands,
            hit_counters=args.dev_counters,
            build_marker=args.dev_marker,
            handler_timing=args.dev_timing,
            log_responses=args.dev_log_response,
            state_snapshots=args.dev_snapshots,
            dev_endpoint=args.dev_endpoint,
            lab_traps=args.lab_traps,
        )
        dev_options.validate()
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    opts = PatchOptions(
        campaign_gold=(args.all or args.campaign_gold),
        campaign_xp=(args.all or args.campaign_xp),
        no_equip_drops=(args.all or args.no_equip_drops),
        gene_priority=(args.all or args.gene_priority),
        summon_rates=summon_70_20_10,
        summon_rates_50_30_20=summon_50_30_20,
        expedition_bonus=(args.all or args.expeditions),
        english_localization=(args.all or args.english),
        event_discount=(args.all or args.event_discount),
        event_gene_unlimited=(args.all or args.event_gene_unlimited),
        event_limits_daily=(args.all or args.event_limits_daily),
        mythical_stone_shop=(args.all or args.mythical_stone_shop),
        hero_shop_offers=(args.all or args.hero_shop_offers),
        surprise_transcendence_package=(args.all or args.surprise_transcendence_package),
        alex_awakening=(args.all or args.alex_awakening),
        alex_rebalance=(args.all or args.alex_rebalance),
        costume_packages_all=(args.all or args.costume_packages_all),
        recycle_six_star=(args.all or args.recycle_six_star),
        energy_flask_x10=(args.all or args.energy_flask_x10),
        option_max_attributes=(args.all or args.option_max_attributes),
        rune_box_random_type=(args.all or args.rune_box_random_type),
        rune_box_random_roll=(args.all or args.rune_box_random_roll),
        equipment_lock_fix=(args.all or args.equipment_lock_fix),
        equipment_single_mod_stone=(args.all or args.equipment_single_mod_stone),
        equipment_percent_options=(args.all or args.equipment_percent_options),
        equipment_upgrade_10_guarantee=(
            args.all or args.equipment_upgrade_10_guarantee
        ),
        limit_break_cost_tenth=limit_cost_tenth,
        limit_break_cost_fixed=limit_cost_fixed,
        soulgear_enchant_always=(args.all or args.soulgear_enchant_always),
        rune_quality_factor=(
            args.rune_quality_factor
            if args.rune_quality_factor
            else (10 if args.all else 0)
        ),
        rune_option_quality=(args.all or args.rune_option_quality),
        rune_upgrade_discount=(args.all or args.rune_upgrade),
        gold_cylinder_x10=(args.all or args.gold_cylinder_x10),
        mana_cylinder_x10=(args.all or args.mana_cylinder_x10),
        event_coin_x10=(args.all or args.event_coin_x10),
        guild_raid_score_fix=(args.all or args.guild_raid_score_fix),
        guild_raid_fire_support=(args.all or args.guild_raid_fire_support),
        guild_raid_protection_persist=(args.all or args.guild_raid_protection_persist),
        alex_heros_mark=(args.all or args.alex_heros_mark),
        guild_raid_skills_max=(args.all or args.guild_raid_skills_max),
        guild_raid_boss_no_counter=(args.all or args.guild_raid_boss_no_counter),
        single_black_hammer=(args.all or args.single_black_hammer),
        equipment_tier_upgrades=(args.all or args.equipment_tier_upgrades),
        single_gem_fang=(args.all or args.single_gem_fang),
        upgrade_no_fail_above_20=(args.all or args.upgrade_no_fail),
        battle_arena_save_fix=(args.all or args.battle_arena_save_fix),
        sacred_lands_restore=(args.all or args.sacred_lands_restore),
        coocoo_exp_x2=(args.all or args.coocoo_exp_x2),
        coocoo_level_x2=(args.all or args.coocoo_level_x2),
        ship_parts_90_off=(args.all or args.ship_parts_90_off),
        worldboss_full_ship_repair=(args.all or args.worldboss_full_ship_repair),
        crystal_skill_90_off=(args.all or args.crystal_skill_90_off),
        gem_mining_x10=(args.all or args.gem_mining_x10),
        gem_mining_types=(args.all or args.gem_mining_types),
        gem_level6=(args.all or args.gem_level6),
        gem_upgrade_gold_half=(args.all or args.gem_upgrade_gold_half),
        stamina_cost_half=stamina_half,
        stamina_potion_1000=(args.all or args.stamina_potion_1000),
        campaign_shop_discount=(args.all or args.campaign_shop_discount),
        mode_drops_x10=(args.all or args.mode_drops_x10),
        devil_boost_x10=(args.all or args.devil_boost_x10),
        battle_arena_fix=(args.all or args.battle_arena_fix),
        guild_raid_mercenary=(args.all or args.guild_raid_mercenary),
        guild_raid_reward_x10=(args.all or args.guild_raid_reward_x10),
        lan_redirect=lan_redirect,
        server_ip=lan_ip,
        server_port=lan_port,
        align_16k=not args.no_16k,
        allow_unknown=args.force,
        dev=dev_options,
    )

    if not _has_selected_feature(opts):
        print(
            "Error: no patch features selected. Pass --all, at least one "
            "feature flag, or a dev instrumentation flag with --dev (see --help).",
            file=sys.stderr,
        )
        return 2

    keystore_default = os.environ.get("FWT_KEYSTORE", "keystore/fwt_reborn_lan.jks")
    keystore_path = (
        Path(args.keystore).expanduser()
        if args.keystore
        else (PROJECT_ROOT / keystore_default).expanduser()
    )

    print(f"Building patched APK: {input_apk.name} -> {output_apk.name}")
    non_feature = {"lan_redirect", "server_ip", "server_port", "align_16k", "allow_unknown", "dev"}
    enabled_features: list[str] = []
    for item in fields(opts):
        if item.name in non_feature:
            continue
        val = getattr(opts, item.name)
        if isinstance(val, bool) and val:
            enabled_features.append(item.name)
        elif not isinstance(val, bool) and isinstance(val, int) and val > 0:
            enabled_features.append(f"{item.name}={val}")
    print(
        f"Options ({len(enabled_features)} feature(s)): "
        f"{', '.join(enabled_features) or 'none'} | "
        f"lan={opts.lan_redirect} ({opts.server_ip}:{opts.server_port}), "
        f"16k={opts.align_16k}, force={opts.allow_unknown}, "
        f"dev={dev_options.enabled} "
        f"[{','.join(dev_options.instrumentation()) or 'no instrumentation'}]"
    )

    dev_id = None
    if args.install or args.uninstall:
        dev_id, error = _resolve_device(adb, args.device)
        if not dev_id:
            print(f"Error: {error}", file=sys.stderr)
            return 1

    if args.install and dev_id and not args.no_backup:
        state = adb.package_state(dev_id)
        if state == "installed":
            print(f"Pre-install backup from {dev_id}...")
            ok, msg = adb.backup_save(dev_id, _backup_path())
            if not ok:
                print(
                    "Error: pre-install backup failed; aborting installation.\n"
                    f"{msg}\n"
                    "Use --no-backup only if you accept the risk of losing the save.",
                    file=sys.stderr,
                )
                return 1
            print(f"Backup OK: {msg}")
        elif state == "unknown":
            print(
                "Error: could not determine whether the package is installed "
                "(adb/device error); refusing to install without a verified backup. "
                "Reconnect the device or pass --no-backup explicitly.",
                file=sys.stderr,
            )
            return 1
        else:
            print("Package is not installed yet; skipping pre-install save backup.")

    try:
        patch_result = repack_and_sign_apk(
            input_apk=input_apk,
            output_apk=output_apk,
            options=opts,
            tools=tools,
            keystore_path=keystore_path,
            log_fn=print,
        )
    except Exception as exc:
        print(f"Error: patching failed: {exc}", file=sys.stderr)
        return 1

    print("Applied patch counts:")
    for name, count in patch_result.counts.items():
        print(f"  {name}: {count}")
    for warning in patch_result.warnings:
        print(f"WARNING: {warning}", file=sys.stderr)

    if os.environ.get("FWT_SKIP_VERIFY") == "1":
        print("Verification skipped (FWT_SKIP_VERIFY=1; debug build)")
    else:
        print("Verifying generated APK...")
        report = inspect_apk(output_apk)
        problems = verify_report(report, opts)
        if problems:
            print("Error: generated APK failed verification:", file=sys.stderr)
            for problem in problems:
                print(f"  - {problem}", file=sys.stderr)
            return 1
        print(
            f"Verification passed: {sum(1 for f in report.features.values() if f.active)} "
            f"active feature report(s), 16KB={report.alignment_16k}, "
            f"signed={report.is_signed}, DEX checksums={report.dex_checksum_valid}"
        )

    # Only remove the installed package after a verified build exists.
    if args.uninstall and dev_id:
        print(f"Uninstalling {dev_id} package...")
        ok, msg = adb.uninstall_apk(dev_id)
        if not ok:
            print(f"Error: {msg}", file=sys.stderr)
            return 1
        print(f"Uninstall OK: {msg}")

    if args.install and dev_id:
        print(f"Installing {output_apk.name} to {dev_id}...")
        ok, msg = adb.install_apk(dev_id, output_apk, log_fn=print)
        if not ok:
            print(f"Error: {msg}", file=sys.stderr)
            return 1
        print(msg)

    if args.restore and args.install and dev_id:
        ok, msg = adb.restore_save(dev_id, Path(args.restore).expanduser())
        if not ok:
            print(f"Error: {msg}", file=sys.stderr)
            return 1
        print(f"Restore OK: {msg}")

    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="FWT Reborn - Offline Client Patcher & Modding Suite",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--gui", action="store_true", help="Launch Graphical User Interface (default if no args)")
    parser.add_argument("--version", action="version", version=f"{APP_NAME} {APP_VERSION}")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--check-tools", action="store_true", help="Check Python dependencies, Android SDK Build-Tools and JDK tools, then exit")
    modes.add_argument("--inspect", type=str, help="Inspect specified APK and display patch report")
    modes.add_argument("--inspect-so", type=str, help="Inspect a standalone libfwt_local_server.so")
    modes.add_argument("--backup", action="store_true", help="Backup savegame from connected ADB device")
    modes.add_argument("--restore", type=str, metavar="JSON", help="Restore a savegame JSON (requires root)")
    modes.add_argument("--uninstall", action="store_true", help="Uninstall com.nexon.fwar (wipes app data; combine with --install to reinstall)")
    parser.add_argument("--device", type=str, help="Target ADB device ID (e.g. 192.0.2.10:5555)")
    parser.add_argument("--input", "-i", type=str, help="Base input APK path")
    parser.add_argument("--output", "-o", type=str, help="Destination patched APK path")
    parser.add_argument("--keystore", type=str, help="Signing keystore path (default: keystore/fwt_reborn_lan.jks)")

    # Features
    parser.add_argument("--all", action="store_true", help="Enable all custom gameplay and localization patches (uses 50/30/20 summon and the 50%% server-side stamina debit; combine with --summon-rates for 70/20/10)")
    parser.add_argument(
        "--dev",
        action="store_true",
        help=(
            "Dev build master switch: enables reverse-engineering instrumentation "
            "and forces a *-dev.apk output (never distribute a dev build)"
        ),
    )
    parser.add_argument(
        "--dev-keep-version",
        action="store_true",
        help="Do not append '-dev' to android:versionName (keeps it identical to "
        "the release, for builds whose version string the game validates)",
    )
    parser.add_argument(
        "--dev-debuggable",
        action="store_true",
        help="Set android:debuggable=true in the manifest (run-as/JDWP without root)",
    )
    parser.add_argument(
        "--dev-log",
        action="store_true",
        help="Log every embedded-server request/response to logcat (tag FWTR-DEV)",
    )
    parser.add_argument(
        "--dev-log-limit",
        type=int,
        default=1024,
        metavar="BYTES",
        help="Max bytes logged per message; 0 logs whole bodies (default 1024)",
    )
    parser.add_argument(
        "--dev-log-commands",
        type=str,
        default="",
        metavar="CSV",
        help="Only log the bodies of these commands (empty logs every command)",
    )
    parser.add_argument(
        "--dev-counters",
        action="store_true",
        help="Track per-patch execution counters",
    )
    parser.add_argument(
        "--dev-marker",
        action="store_true",
        help="Log the build marker (version + short hash) at boot",
    )
    parser.add_argument(
        "--dev-log-response",
        action="store_true",
        help="Log the response body of every command (needs the dispatcher exit hook)",
    )
    parser.add_argument(
        "--dev-timing",
        action="store_true",
        help="Log slow embedded-server handlers (cntvct_el0 timing)",
    )
    parser.add_argument(
        "--dev-snapshots",
        action="store_true",
        help="Emit numbered state snapshots for diffing",
    )
    parser.add_argument(
        "--dev-endpoint",
        action="store_true",
        help="Expose a DEV_DUMP command on the embedded server",
    )
    parser.add_argument(
        "--lab-traps",
        action="store_true",
        help="Laboratory: brk #0 dead-code traps (crashes on purpose)",
    )
    parser.add_argument("--campaign-gold", action="store_true", help="Enable 10x Campaign Gold & Drops")
    parser.add_argument("--campaign-xp", action="store_true", help="Enable 10x Campaign XP")
    parser.add_argument("--no-equip-drops", action="store_true", help="Remove equipment from stage drops and redistribute their weight to other drops")
    parser.add_argument("--gene-priority", action="store_true", help="Enable Hero Gene Drop Priority")
    summon = parser.add_mutually_exclusive_group()
    summon.add_argument("--summon-rates", action="store_true", help="Enable 70/20/10 Summon Rates (70%% 4*, 20%% 5*, 10%% 6*)")
    summon.add_argument("--summon-50-30-20", action="store_true", help="Enable 50/30/20 Summon Rates (50%% 4*, 30%% 5*, 20%% 6*)")
    parser.add_argument("--expeditions", action="store_true", help="Enable 10x Expedition Rewards")
    parser.add_argument("--english", action="store_true", help="Enable English Localization")
    parser.add_argument("--event-discount", action="store_true", help="Enable 90%% Event Shop Discount")
    parser.add_argument("--event-gene-unlimited", action="store_true", help="Remove Event Shop gene purchase limits (unlimited)")
    parser.add_argument("--event-limits-daily", action="store_true", help="Convert event-limited shop items (limit_type=3) to daily limits")
    parser.add_argument("--mythical-stone-shop", action="store_true", help="Add Mythical Stone to the Event Shop and increase the Balance Jade daily limit")
    parser.add_argument("--hero-shop-offers", action="store_true", help="Offer Evan and Alex genes and increase the Honor Shop diamond bundle")
    parser.add_argument("--surprise-transcendence-package", action="store_true", help="Offer 10 Ultimate and 10 Universal Transcendence Tickets for 500 diamonds in Surprise Sale package 2")
    parser.add_argument("--alex-awakening", action="store_true", help="Enable Alex's original Awakening and Destiny Lance")
    parser.add_argument("--alex-rebalance", action="store_true", help="Rebalance Alex Skills 1-3, Passive, and Destiny Lance 1-cell Thornbush")
    parser.add_argument("--alex-heros-mark", action="store_true", help="Give Alex a Hero's Mark (The Unbroken Lance): Destiny Lance +25%% per mark level and first-turn cast at Lv10; team-wide set effects")
    parser.add_argument("--costume-packages-all", action="store_true", help="Give one copy of each eligible owned costume from packages 3 and 4, up to ten times daily per package")
    parser.add_argument(
        "--recycle-six-star",
        action="store_true",
        help=(
            "Recycling keeps the native equipment reward and grants a 6★ "
            "piece (grade 5 + secret grade 3); included in --all"
        ),
    )
    parser.add_argument("--energy-flask-x10", action="store_true", help="Energy Flask awards 1000 stamina instead of 100 (keeps the 12-15h and 18-21h windows)")
    parser.add_argument("--option-max-attributes", action="store_true", help="Option-change potions roll with the maximum quality bias (best attributes)")
    parser.add_argument("--rune-box-random-type", action="store_true", help="The 4-star random rune box rolls any of the three basic rune types instead of a single rejected one")
    parser.add_argument("--soulgear-enchant-always", action="store_true", help="Gold-paid soulgear enchant succeeds every time (soulgear upgrade has no roll)")
    parser.add_argument("--equipment-lock-fix", action="store_true", help="Locked equipment option lines survive the first roll (the handler used to re-roll them before reading lock_list)")
    parser.add_argument("--equipment-single-mod-stone", action="store_true", help="Charge one Modification Stone per equipment option change regardless of locked lines")
    parser.add_argument("--equipment-percent-options", action="store_true", help="Remove flat equipment option rolls; only percentage options (+X%%) are drawn")
    parser.add_argument("--equipment-upgrade-10-guarantee", action="store_true", help="Make the +9 -> +10 equipment upgrade succeed on the first attempt")
    parser.add_argument("--rune-box-random-roll", action="store_true", help="Rune box draws its slot and type randomly again (the dev's deterministic roll is kept for grade/quality and the fourth attribute)")
    parser.add_argument("--rune-quality-factor", type=int, default=0, metavar="N", help="Scale rune attribute mastery bias by N (450 * N, capped at 10000) and exclude fixed-value attributes; N=0 disables both changes")
    parser.add_argument("--rune-option-quality", action="store_true", help="Rune rolls always use the maximum Lord mastery weight row")
    parser.add_argument("--rune-upgrade", action="store_true", help="Rune upgrades +12..+15 always succeed and cost a tenth of the gold")
    parser.add_argument("--gold-cylinder-x10", action="store_true", help="Gold Cylinder yields 10x gold per collection")
    parser.add_argument("--mana-cylinder-x10", action="store_true", help="Mana Stone Compactor yields 10x mana per charge")
    parser.add_argument("--event-coin-x10", action="store_true", help="Enable 10x Event Coin Drop on Campaign Stages")
    parser.add_argument("--campaign-shop-discount", action="store_true", help="Enable 90%% discount across campaign shops (Honor, Ancient Coins, Guild Raid, Unknown Paradise, and Friend Shop)")
    parser.add_argument("--mode-drops-x10", action="store_true", help="Enable 10x drops across 6 game modes (Unknown Paradise, Battle of Honor, Dimension Breakthrough, Pit of Nephthys, Sky Library, Lost Island); Battle of Honor rank points are x2 on victory")
    parser.add_argument("--devil-boost-x10", action="store_true", help="Multiply the Devil's Soul EXP-synthesis boost by 10 (2x -> 20x)")
    parser.add_argument("--battle-arena-fix", action="store_true", help="Fix Battle Arena/PvP team saving (compacts 8 members to 4 leaders) and empty slot handling")
    parser.add_argument("--guild-raid-mercenary", action="store_true", help="Allow selecting own mercenary with equipment and stats in Guild Raid")
    parser.add_argument("--guild-raid-reward-x10", action="store_true", help="Multiply the Guild Raid daily/weekly rank reward mails (items + gold) by 10")
    parser.add_argument("--guild-raid-score-fix", action="store_true", help="Enable 64-bit Guild Raid scores above 2.5B")
    parser.add_argument(
        "--guild-raid-fire-support",
        action="store_true",
        help="Make Fire Support deal 100%% maxHp to minions and auto-fire only at the start of odd turns when reserved",
    )
    parser.add_argument(
        "--guild-raid-skills-max",
        action="store_true",
        help="Max the other 3 Guild Raid skills (1M Shelling boss dmg, 100%% 1-hit DR/HP/MP, 20 debuffs dispelled)",
    )
    parser.add_argument(
        "--guild-raid-boss-no-counter",
        action="store_true",
        help="Set Guild Raid boss counterattack rate to 0%% (down from 300 / 3%%)",
    )
    parser.add_argument(
        "--guild-raid-protection-persist",
        action="store_true",
        help="Make Absolute Protection reduce every hit on protected allies until its turn expiry instead of only the first hit",
    )
    parser.add_argument("--single-black-hammer", action="store_true", help="Use 1 black hammer per +16..+26 transcendence attempt")
    parser.add_argument("--equipment-tier-upgrades", action="store_true", help="Use one hammer to complete an equipment transcendence tier")
    parser.add_argument("--single-gem-fang", action="store_true", help="Use 1 Dragon Fang to open all 3 equipment gem slots at once")
    parser.add_argument("--upgrade-no-fail", action="store_true", help="Make equipment upgrades above +20 always succeed (no insurance card needed)")
    parser.add_argument("--battle-arena-save-fix", action="store_true", help="Fix the Battle Arena team Save button (client runtime hook)")
    parser.add_argument("--sacred-lands-restore", action="store_true", help="Restore the Sacred Lands set: fix its client grade and add it to the set selection tickets")
    limit_break_group = parser.add_mutually_exclusive_group()
    limit_break_group.add_argument("--limit-break-cost-tenth", action="store_true", help="Reduce hero limit break (Awake) gold and material cost by 90%%")
    limit_break_group.add_argument("--limit-break-cost-fixed", action="store_true", help="Charge a flat 1,000,000 gold and 100 Balance Jade for every hero limit break (overrides the 90%% discount)")
    parser.add_argument("--coocoo-exp-x2", action="store_true", help="Always apply the x2 EXP bonus when leveling heroes with coocoos")
    parser.add_argument("--coocoo-level-x2", action="store_true", help="Double the coocoo levels dropped by the 30 Coocoo Garden / Pit of Nephthys stages (final stage 220 -> 440)")
    parser.add_argument(
        "--ship-parts-90-off",
        "--ship-parts-half",
        dest="ship_parts_90_off",
        action="store_true",
        help="Reduce Unknown Paradise battleship part gold upgrade costs by 90%% (--ship-parts-half is kept as a legacy alias)",
    )
    parser.add_argument("--crystal-skill-90-off", action="store_true", help="Reduce Unknown Paradise core crystal upgrade costs by 90%% (50 -> 5 Kraken Scales)")
    parser.add_argument("--worldboss-full-ship-repair", action="store_true", help="Restore full ship HP on successful Unknown Paradise repair")
    parser.add_argument("--gem-mining-x10", action="store_true", help="Award 10 gems per paid gem-mining roll (20 crystals), same gem type")
    parser.add_argument("--gem-level6", action="store_true", help="Gems obtained or bought in the lobby gem screen are level 6 instead of level 1")
    parser.add_argument("--gem-mining-types", action="store_true", help="Restrict gem-mining rolls to MP, Counter Rate, Counter Damage, Dodge and Hit Rate")
    parser.add_argument("--gem-upgrade-gold-half", action="store_true", help="Halve the gold fee charged by lobby gem upgrades")
    parser.add_argument("--stamina-cost-half", action="store_true", help="Server-side 50%% dungeon stamina debit (used by --all; the client may still display/validate the full cost)")
    parser.add_argument("--stamina-potion-1000", action="store_true", help="Make normal Stamina Potions restore 1000 points instead of max stamina")
    parser.add_argument("--lan", type=parse_lan_endpoint, metavar="IP[:PORT]", help="Redirect loopback to LAN server (e.g. 192.0.2.20:8010)")
    parser.add_argument("--no-16k", action="store_true", help="Disable 16 KB page-alignment (use 4 KB)")
    parser.add_argument("--install", action="store_true", help="Install patched APK to device via ADB after building")
    parser.add_argument("--no-backup", action="store_true", help="Skip the automatic pre-install save backup (dangerous)")
    parser.add_argument("--force", action="store_true", help="Allow patching a non-reference APK (advanced, unsafe)")

    return parser


def _launch_gui() -> int:
    try:
        from gui.main_window import MainWindow
    except Exception as exc:
        print(f"Error: could not start GUI: {exc}", file=sys.stderr)
        return 1
    app = MainWindow(project_root=PROJECT_ROOT)
    app.mainloop()
    return 0


def main() -> int:
    _configure_console()
    _load_env_file()
    parser = build_parser()
    if len(sys.argv) == 1:
        return _launch_gui()

    args = parser.parse_args()
    if not args.device:
        args.device = os.environ.get("FWT_DEVICE") or None
    if args.gui:
        if len(sys.argv) > 2:
            parser.error("--gui cannot be combined with other options")
        return _launch_gui()

    try:
        return run_cli(args)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        if os.environ.get("FWT_DEBUG"):
            raise
        return 1


if __name__ == "__main__":
    sys.exit(main())
