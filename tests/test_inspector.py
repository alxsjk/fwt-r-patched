from __future__ import annotations

import struct
import zipfile
from pathlib import Path

import pytest

from core.apk_tooling import (
    LIMIT_BREAK_CLIENT_ASSET_PATH,
    _patch_resources_zip_file,
)
from core.core_patches import (
    CAMPAIGN_CAVE_BASE,
    DIMENSION_CAVE_VADDR,
    RECYCLE_SIX_STAR_CLIENT_ASSETS,
    RIDDLE_TABLE_OFFSET,
    RUNE_QUALITY_BONUS_REGISTER,
    RUNE_QUALITY_BONUS_SITE,
    SOULGEAR_ENCHANT_REGISTER,
    SOULGEAR_ENCHANT_SITE,
    STAGE_ROW_SIZE,
    STAGE_TABLE_OFFSET,
    WORLDBOSS_CYCLE_REWARD_VADDR,
    WORLDBOSS_DAILY_KRAKEN_CAVE_VADDR,
    WORLDBOSS_EVENT_REWARD_SITE,
    WORLDBOSS_REWARD_CLIENT_ASSETS,
    PatchOptions,
    apply_all_patches,
    apply_rune_quality_factor,
    apply_soulgear_enchant_always,
    encode_arm64_branch,
    encode_movz_w,
    encode_movz_x,
    seg_offset,
)
from core.dex_smali import find_apktool_jar, find_java_executable
from core.patch_inspector import (
    InspectionReport,
    detect_cave_overlap,
    expected_feature_keys,
    inspect_apk,
    inspect_dex,
    inspect_native_so,
    verify_report,
)


def test_source_is_pristine_and_inactive(reference_buffers):
    so_bytes, dex_bytes = reference_buffers
    native = inspect_native_so(so_bytes)
    # Guard against an inspector regression that returns an empty dict and
    # makes every() below pass vacuously.
    assert len(native) >= 40
    assert {"campaign_gold", "event_coin_x10", "summon_rates"} <= native.keys()
    assert all(not feature.active for feature in native.values())
    assert not inspect_dex(dex_bytes)["dex_status_string"].active
    assert detect_cave_overlap(so_bytes) is False


def test_patched_features_are_all_detected(reference_buffers):
    so_bytes, dex_bytes = reference_buffers
    jar = find_apktool_jar()
    if jar is None:
        pytest.skip("apktool jar not available; set FWT_APKTOOL_JAR to run this test")
    if find_java_executable() is None:
        pytest.skip("Java runtime not found; install a JRE/JDK or set JAVA_HOME to run this test")
    options = PatchOptions(
        campaign_gold=True,
        campaign_xp=True,
        no_equip_drops=True,
        gene_priority=True,
        summon_rates_50_30_20=True,
        expedition_bonus=True,
        english_localization=True,
        event_discount=True,
        event_gene_unlimited=True,
        event_limits_daily=True,
        recycle_six_star=True,
        energy_flask_x10=True,
        gold_cylinder_x10=True,
        mana_cylinder_x10=True,
        event_coin_x10=True,
        mode_drops_x10=True,
        devil_boost_x10=True,
        upgrade_no_fail_above_20=True,
        limit_break_cost_tenth=True,
        coocoo_exp_x2=True,
        gem_mining_x10=True,
        gem_upgrade_gold_half=True,
        stamina_cost_half=True,
        stamina_potion_1000=True,
        guild_raid_reward_x10=True,
    )
    result = apply_all_patches(so_bytes, dex_bytes, options, apktool_jar=jar)
    features = inspect_native_so(result.so_bytes)
    features.update(inspect_dex(result.dex_bytes))

    expected = expected_feature_keys(options)
    for key, name in expected.items():
        assert key in features, f"missing feature key {key}"
        assert features[key].active, f"{name} was not detected as active"

    assert detect_cave_overlap(result.so_bytes) is False
    assert features["event_coin_x10"].active
    assert features["campaign_gold"].active
    assert features["expedition_bonus"].active
    assert features["summon_rates_50_30_20"].active
    assert not features["summon_rates"].active
    assert features["event_gene_unlimited"].active
    assert features["event_limits_daily"].active
    assert features["mode_drops_x10"].active
    assert features["devil_boost_x10"].active
    assert features["limit_break_cost_tenth"].active
    assert features["gold_cylinder_x10"].active
    assert features["mana_cylinder_x10"].active
    assert features["no_win_box"].active
    assert features["hero_exp_cap"].active
    assert features["coocoo_exp_x2"].active
    assert features["gem_upgrade_gold_half"].active
    assert features["stamina_cost_half"].active
    assert features["stamina_potion_1000"].active


def test_verify_report_rejects_missing_feature(reference_buffers):
    so_bytes, dex_bytes = reference_buffers
    options = PatchOptions(campaign_xp=True, event_coin_x10=True)
    features = inspect_native_so(so_bytes)
    features.update(inspect_dex(dex_bytes))
    report = InspectionReport(
        is_valid_apk=True,
        has_so=True,
        has_dex=True,
        features=features,
        alignment_16k=True,
        is_signed=True,
        dex_checksum_valid=True,
    )
    problems = verify_report(report, options)
    assert any("10x Campaign XP" in problem for problem in problems)
    assert any("10x Campaign Event Coin" in problem for problem in problems)


def test_legacy_overlap_is_detected(reference_buffers):
    so_bytes, _ = reference_buffers
    legacy = bytearray(so_bytes)
    # Simulate the old buggy build: event coin cave at the items-cave address.
    legacy[0x8D05B8 - 0x4000:0x8D05B8 - 0x4000 + 4] = encode_arm64_branch(
        0x8D05B8, 0xAA6CAC
    )
    legacy[0xAA6CAC - 0x4000:0xAA6CAC - 0x4000 + 12] = bytes.fromhex(
        "48018052737e089b43a6f817"
    )
    assert detect_cave_overlap(legacy) is True


def test_expected_feature_keys_mapping():
    options = PatchOptions(english_localization=True, lan_redirect=True)
    keys = expected_feature_keys(options)
    assert keys["english_localization"] == "English Localization"
    assert keys["dex_status_string"] == "Bootstrap Status String"
    assert keys["network_mode"] == "Network Mode"
    assert keys["dex_backup_prompt"] == "Save Backup Dialog"
    assert CAMPAIGN_CAVE_BASE == 0xB33314


def test_upgrade_report_requires_client_resource_table():
    from core.patch_inspector import FeatureReport, _inspect_apk_resources

    features = {
        "equipment_upgrade_10_guarantee": FeatureReport("upgrade", True, "Active")
    }
    _inspect_apk_resources(None, features)
    assert not features["equipment_upgrade_10_guarantee"].active
    assert "client upgrade table unchecked" in features["equipment_upgrade_10_guarantee"].details


def test_shop_reports_require_client_tables():
    from core.patch_inspector import FeatureReport, _inspect_apk_resources

    keys = ("event_discount", "campaign_shop_discount", "event_gene_unlimited", "event_limits_daily")
    features = {key: FeatureReport(key, True, "Active") for key in keys}
    _inspect_apk_resources(None, features)
    assert all(not features[key].active for key in keys)


def test_verify_report_rejects_wrong_parameter_values():
    from core.patch_inspector import FeatureReport

    options = PatchOptions(rune_quality_factor=10, lan_redirect=True,
                           server_ip="192.168.1.2", server_port=8010)
    report = InspectionReport(
        is_valid_apk=True, has_so=True, has_dex=True, alignment_16k=True,
        is_signed=True, dex_checksum_valid=True,
        features={
            "rune_quality_factor": FeatureReport("rune", True, "active", value=450),
            "network_mode": FeatureReport("lan", True, "active", value=("192.168.1.3", 8010)),
            "dex_backup_prompt": FeatureReport("prompt", True, "active"),
            "no_win_box": FeatureReport("fix", True, "active"),
            "hero_exp_cap": FeatureReport("fix", True, "active"),
        },
    )
    problems = verify_report(report, options)
    assert any("Rune quality bonus differs" in problem for problem in problems)
    assert any("LAN endpoint differs" in problem for problem in problems)


def test_signature_inspector_rejects_fake_rsa(tmp_path, monkeypatch):
    import zipfile

    from core import apk_tooling
    from core.patch_inspector import check_apk_signatures

    apk = tmp_path / "fake.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("META-INF/FAKE.RSA", b"not a signature")
    monkeypatch.setattr(apk_tooling, "locate_tools", lambda: apk_tooling.ToolPaths(apksigner="apksigner"))

    def reject(*args, **kwargs):
        raise RuntimeError("invalid signature")

    monkeypatch.setattr(apk_tooling, "_run_tool", reject)
    signed, detail = check_apk_signatures(apk)
    assert not signed
    assert "invalid signature" in detail


def test_inspect_reads_complete_recipe(reference_manifest, tmp_path):
    import json
    import zipfile
    from dataclasses import asdict

    from core.patch_inspector import inspect_apk
    from core.version import BUILD_IDENTITY_ENTRY

    manifest, _ = reference_manifest
    options = PatchOptions(campaign_gold=True, rune_quality_factor=10)
    apk = tmp_path / "artifact.apk"
    recorded = asdict(options)
    payload = {"identity": "release", "options": recorded}
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", manifest)
        archive.writestr(BUILD_IDENTITY_ENTRY, json.dumps(payload))
    report = inspect_apk(apk)
    assert report.build_identity == "release"
    assert report.build_options == options

    recorded.pop("campaign_gold")
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", manifest)
        archive.writestr(BUILD_IDENTITY_ENTRY, json.dumps(payload))
    assert inspect_apk(apk).build_identity == "unknown"


def test_movz_detectors_reject_partial_and_invalid_opcodes(reference_buffers):
    so_bytes, _ = reference_buffers

    # Rune quality factor: valid `movz x<reg>` active; 32-bit `movz w<reg>`, wrong reg, or hw!=0 inactive.
    rune_ok = bytearray(so_bytes)
    apply_rune_quality_factor(rune_ok, 10)
    rune_rep = inspect_native_so(rune_ok)["rune_quality_factor"]
    assert rune_rep.active is True
    assert "4500" in rune_rep.status

    rune_off = seg_offset(RUNE_QUALITY_BONUS_SITE)
    rune_w = bytearray(rune_ok)
    rune_w[rune_off:rune_off + 4] = encode_movz_w(RUNE_QUALITY_BONUS_REGISTER, 4500)
    assert inspect_native_so(rune_w)["rune_quality_factor"].active is False

    rune_hw = bytearray(rune_ok)
    rune_hw[rune_off:rune_off + 4] = struct.pack(
        "<I", 0xD2A00000 | (1 << 5) | RUNE_QUALITY_BONUS_REGISTER
    )
    assert inspect_native_so(rune_hw)["rune_quality_factor"].active is False

    # Soulgear enchant: valid `movz w<reg>` active; branch garbage inactive.
    sg_ok = bytearray(so_bytes)
    apply_soulgear_enchant_always(sg_ok)
    assert inspect_native_so(sg_ok)["soulgear_enchant_always"].active is True

    sg_bad = bytearray(sg_ok)
    sg_off = seg_offset(SOULGEAR_ENCHANT_SITE)
    sg_bad[sg_off:sg_off + 4] = encode_movz_x(SOULGEAR_ENCHANT_REGISTER, 1)
    assert inspect_native_so(sg_bad)["soulgear_enchant_always"].active is False


def test_dex_backup_prompt_ignores_short_random_fragments(reference_buffers):
    so_bytes, dex_bytes = reference_buffers
    res = apply_all_patches(so_bytes, dex_bytes, PatchOptions(lan_redirect=True))

    # Original reference DEX reports Original.
    assert inspect_dex(dex_bytes, res.so_bytes)["dex_backup_prompt"].active is False

    # Wipe both full original sequences cleanly and inject the legacy 4/6-byte false positives.
    cleaned = bytearray(dex_bytes)
    for sig in (
        b"\x71\x10\xf0\x00\x00\x00\x0a\x00\x38\x00\x19\x00",
        b"\x62\x09\x6d\x00\x16\x05\x02\x00\x78\x07\xae\x01\x03\x00",
    ):
        idx = cleaned.find(sig)
        assert idx != -1
        cleaned[idx:idx + len(sig)] = b"\x00" * len(sig)
    decoy_dex = bytes(cleaned) + b"\x38\x00\x19\x00\x78\x07\xae\x01\x03\x00"
    rep = inspect_dex(decoy_dex, res.so_bytes)["dex_backup_prompt"]
    assert rep.active is True
    assert rep.status == "Bypassed"


def test_inspect_apk_checks_limitbreakcost_client_resource(tmp_path: Path, reference_buffers):
    so_bytes, dex_bytes = reference_buffers
    res = apply_all_patches(so_bytes, dex_bytes, PatchOptions(limit_break_cost_tenth=True))

    source_apk = (
        Path(__file__).resolve().parents[1]
        / "source"
        / "fwt_0.682_offline_v1574.apk"
    )
    raw_res = tmp_path / "raw_res.zip"
    with (
        zipfile.ZipFile(source_apk, "r") as zf,
        zf.open("assets/fwt_resources_v1.zip") as inner_file,
        zipfile.ZipFile(inner_file, "r") as inner_zip,
        zipfile.ZipFile(raw_res, "w") as slim_res,
    ):
        slim_res.writestr(
            LIMIT_BREAK_CLIENT_ASSET_PATH,
            inner_zip.read(LIMIT_BREAK_CLIENT_ASSET_PATH),
        )

    # 1) Missing resources zip -> inactive
    no_res_apk = tmp_path / "no_res.apk"
    with zipfile.ZipFile(no_res_apk, "w") as zf:
        zf.writestr("lib/arm64-v8a/libfwt_local_server.so", res.so_bytes)
        zf.writestr("classes8.dex", res.dex_bytes)
    assert inspect_apk(no_res_apk).features["limit_break_cost_tenth"].active is False

    # 2) Stock resources zip with patched SO -> inactive
    stock_res_apk = tmp_path / "stock_res.apk"
    with zipfile.ZipFile(stock_res_apk, "w") as zf:
        zf.writestr("lib/arm64-v8a/libfwt_local_server.so", res.so_bytes)
        zf.writestr("classes8.dex", res.dex_bytes)
        zf.writestr("assets/fwt_resources_v1.zip", raw_res.read_bytes())
    assert inspect_apk(stock_res_apk).features["limit_break_cost_tenth"].active is False

    # 3) Matching patched limitbreakcost.unity3d -> active
    patched_dir = tmp_path / "patched_res"
    patched_dir.mkdir()
    patched_res, _ = _patch_resources_zip_file(
        raw_res,
        PatchOptions(limit_break_cost_tenth=True),
        work_dir=patched_dir,
    )
    ok_apk = tmp_path / "ok.apk"
    with zipfile.ZipFile(ok_apk, "w") as zf:
        zf.writestr("lib/arm64-v8a/libfwt_local_server.so", res.so_bytes)
        zf.writestr("classes8.dex", res.dex_bytes)
        zf.writestr("assets/fwt_resources_v1.zip", patched_res.read_bytes())
    assert inspect_apk(ok_apk).features["limit_break_cost_tenth"].active is True


def test_inspector_detects_partial_campaign_xp_and_mode_drops(reference_buffers):
    so_bytes, dex_bytes = reference_buffers
    res = apply_all_patches(
        so_bytes,
        dex_bytes,
        PatchOptions(campaign_xp=True, mode_drops_x10=True),
    )
    base_feats = inspect_native_so(res.so_bytes)
    assert base_feats["campaign_xp"].active is True
    assert base_feats["mode_drops_x10"].active is True

    # Tampering a later campaign row (row 1) while keeping Stage 100010 patched must fail.
    bad_xp = bytearray(res.so_bytes)
    struct.pack_into("<i", bad_xp, STAGE_TABLE_OFFSET + STAGE_ROW_SIZE + 4, 1)
    assert inspect_native_so(bytes(bad_xp))["campaign_xp"].active is False

    # Tampering WB cycle rewards, event table, daily cave, or Sky Library riddle table must fail mode_drops_x10.
    bad_wb_cycle = bytearray(res.so_bytes)
    struct.pack_into("<q", bad_wb_cycle, seg_offset(WORLDBOSS_CYCLE_REWARD_VADDR) + 0x20, 5_000_000)
    wb_cycle_report = inspect_native_so(bytes(bad_wb_cycle))["mode_drops_x10"]
    assert wb_cycle_report.active is False
    assert "wb_cycle_rewards" in wb_cycle_report.details

    bad_wb = bytearray(res.so_bytes)
    wb_ev_off = seg_offset(WORLDBOSS_EVENT_REWARD_SITE)
    bad_wb[wb_ev_off : wb_ev_off + 4] = b"\x00\x00\x00\x00"
    wb_report = inspect_native_so(bytes(bad_wb))["mode_drops_x10"]
    assert wb_report.active is False
    assert "wb_event" in wb_report.details

    bad_wb_cave = bytearray(res.so_bytes)
    bad_wb_cave[
        seg_offset(WORLDBOSS_DAILY_KRAKEN_CAVE_VADDR) : seg_offset(
            WORLDBOSS_DAILY_KRAKEN_CAVE_VADDR
        )
        + 4
    ] = b"\x1f\x20\x03\xd5"
    wb_cave_report = inspect_native_so(bytes(bad_wb_cave))["mode_drops_x10"]
    assert wb_cave_report.active is False
    assert "wb_daily_kraken" in wb_cave_report.details

    bad_cave = bytearray(res.so_bytes)
    bad_cave[seg_offset(DIMENSION_CAVE_VADDR) : seg_offset(DIMENSION_CAVE_VADDR) + 4] = (
        b"\x1f\x20\x03\xd5"
    )
    cave_report = inspect_native_so(bytes(bad_cave))["mode_drops_x10"]
    assert cave_report.active is False
    assert "dimension_drops" in cave_report.details

    bad_riddle = bytearray(res.so_bytes)
    struct.pack_into("<i", bad_riddle, RIDDLE_TABLE_OFFSET + 20, 1234)
    riddle_report = inspect_native_so(bytes(bad_riddle))["mode_drops_x10"]
    assert riddle_report.active is False
    assert "sky_library_riddle" in riddle_report.details


def test_inspect_apk_checks_honorreward_and_recycle_six_star_resources(
    tmp_path: Path, reference_buffers
):
    so_bytes, dex_bytes = reference_buffers
    options = PatchOptions(mode_drops_x10=True, recycle_six_star=True)
    res = apply_all_patches(so_bytes, dex_bytes, options)

    source_apk = (
        Path(__file__).resolve().parents[1]
        / "source"
        / "fwt_0.682_offline_v1574.apk"
    )
    raw_res = tmp_path / "raw_mode_recycle.zip"
    target_entries = (
        "files/Resources/datatable/honorreward.unity3d",
        *WORLDBOSS_REWARD_CLIENT_ASSETS,
        *RECYCLE_SIX_STAR_CLIENT_ASSETS,
    )
    with (
        zipfile.ZipFile(source_apk, "r") as zf,
        zf.open("assets/fwt_resources_v1.zip") as inner_file,
        zipfile.ZipFile(inner_file, "r") as inner_zip,
        zipfile.ZipFile(raw_res, "w") as slim_res,
    ):
        for entry in target_entries:
            slim_res.writestr(entry, inner_zip.read(entry))

    no_res_apk = tmp_path / "no_res.apk"
    with zipfile.ZipFile(no_res_apk, "w") as zf:
        zf.writestr("lib/arm64-v8a/libfwt_local_server.so", res.so_bytes)
        zf.writestr("classes8.dex", res.dex_bytes)
    no_res_rep = inspect_apk(no_res_apk)
    assert no_res_rep.features["mode_drops_x10"].active is False
    assert no_res_rep.features["recycle_six_star"].active is False

    stock_res_apk = tmp_path / "stock_res.apk"
    with zipfile.ZipFile(stock_res_apk, "w") as zf:
        zf.writestr("lib/arm64-v8a/libfwt_local_server.so", res.so_bytes)
        zf.writestr("classes8.dex", res.dex_bytes)
        zf.writestr("assets/fwt_resources_v1.zip", raw_res.read_bytes())
    stock_rep = inspect_apk(stock_res_apk)
    assert stock_rep.features["mode_drops_x10"].active is False
    assert stock_rep.features["recycle_six_star"].active is False

    patched_dir = tmp_path / "patched_mode_recycle"
    patched_dir.mkdir()
    patched_res, _ = _patch_resources_zip_file(raw_res, options, work_dir=patched_dir)
    ok_apk = tmp_path / "ok_mode_recycle.apk"
    with zipfile.ZipFile(ok_apk, "w") as zf:
        zf.writestr("lib/arm64-v8a/libfwt_local_server.so", res.so_bytes)
        zf.writestr("classes8.dex", res.dex_bytes)
        zf.writestr("assets/fwt_resources_v1.zip", patched_res.read_bytes())
    ok_rep = inspect_apk(ok_apk)
    assert ok_rep.features["mode_drops_x10"].active is True
    assert ok_rep.features["recycle_six_star"].active is True


def test_signature_inspector_passes_absolute_path_to_apksigner(tmp_path, monkeypatch):
    from core import apk_tooling
    from core.patch_inspector import check_apk_signatures

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(apk_tooling, "locate_tools", lambda: apk_tooling.ToolPaths(apksigner="apksigner"))
    captured = []

    def reject(argv, *args, **kwargs):
        captured.append(argv)
        raise RuntimeError("invalid signature")

    monkeypatch.setattr(apk_tooling, "_run_tool", reject)
    signed, _ = check_apk_signatures(Path("relative.apk"))
    assert not signed
    assert captured[0][-1] == str((tmp_path / "relative.apk").resolve())


def test_event_limits_daily_inspector_requires_all_native_sites(monkeypatch):
    import core.elf_mapping as elf_mapping
    import core.patch_inspector as inspector
    from core.core_patches import (
        EVENT_LIMIT_COUNT_CAVE_SIZE,
        EVENT_LIMIT_COUNT_CAVE_VADDR,
        EVENT_LIMIT_COUNT_HOOK_SITE,
        EVENT_LIMIT_PERIOD_ORIGINAL,
        EVENT_LIMIT_PERIOD_SITE,
        EVENT_LIMIT_PERIOD_TARGET,
        EXPECTED_EVENT_LIMIT_ROWS,
        _event_shop_count_cave_bytes,
    )

    site_offsets = {
        EVENT_LIMIT_PERIOD_SITE: 0,
        EVENT_LIMIT_COUNT_HOOK_SITE: 64,
        EVENT_LIMIT_COUNT_CAVE_VADDR: 128,
    }
    monkeypatch.setattr(
        elf_mapping, "canonicalize_segments", lambda data, _segs: (bytes(data), ())
    )
    monkeypatch.setattr(inspector, "seg_offset", lambda va: site_offsets.get(va, 512))

    buf = bytearray(b"\x00" * 1024 + b'"limit_type":1,' * EXPECTED_EVENT_LIMIT_ROWS)
    buf[0:4] = encode_arm64_branch(EVENT_LIMIT_PERIOD_SITE, EVENT_LIMIT_PERIOD_TARGET)
    buf[64:72] = (
        encode_arm64_branch(EVENT_LIMIT_COUNT_HOOK_SITE, EVENT_LIMIT_COUNT_CAVE_VADDR)
        + struct.pack("<I", 0xD503201F)
    )
    buf[128 : 128 + EVENT_LIMIT_COUNT_CAVE_SIZE] = _event_shop_count_cave_bytes()

    assert inspector.inspect_native_so(bytes(buf))["event_limits_daily"].active is True

    for off, replacement in (
        (0, EVENT_LIMIT_PERIOD_ORIGINAL),
        (64, b"\x00" * 8),
        (128, b"\x00" * EVENT_LIMIT_COUNT_CAVE_SIZE),
    ):
        broken = bytearray(buf)
        broken[off : off + len(replacement)] = replacement
        rep = inspector.inspect_native_so(bytes(broken))["event_limits_daily"]
        assert rep.active is False
        assert rep.status == "Original / Partial"


def test_inspect_apk_stays_valid_when_unitypy_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import builtins
    import io
    import sys

    inner_buf = io.BytesIO()
    with zipfile.ZipFile(inner_buf, "w"):
        pass

    apk = tmp_path / "minimal.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("assets/fwt_resources_v1.zip", inner_buf.getvalue())

    for mod in ("UnityPy", "core.alex_awakening_assets", "core.alex_rebalance"):
        monkeypatch.delitem(sys.modules, mod, raising=False)

    real_import = builtins.__import__

    def _block_unitypy(name: str, *args, **kwargs):
        if name == "UnityPy" or name.startswith("UnityPy."):
            raise ImportError("simulated missing UnityPy")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _block_unitypy)
    monkeypatch.setattr(
        "core.patch_inspector.check_apk_alignment",
        lambda _p: (False, "no .so"),
    )
    monkeypatch.setattr(
        "core.patch_inspector.check_apk_signatures",
        lambda _p: (False, "unsigned"),
    )

    report = inspect_apk(apk)
    assert report.is_valid_apk is True
    assert report.features["alex_rebalance"].active is False
    assert "Optional dependencies" in report.features["alex_rebalance"].details
    assert report.features["alex_awakening"].active is False
    assert "Optional dependencies" in report.features["alex_awakening"].details
