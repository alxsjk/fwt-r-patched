"""Tests for hero Limit Break +10 level progression (feature 13.03)."""

from __future__ import annotations

import ast
import hashlib
import struct
import types
import zipfile
from pathlib import Path

import pytest

from core.core_patches import (
    EXPECTED_PATCH_COUNTS,
    IDEMPOTENT_PATCHES,
    LIMIT_BREAK_COST_FIXED_SHA256,
    LIMIT_BREAK_COST_TENTH_SHA256,
    LIMIT_BREAK_FIXED_GOLD,
    LIMIT_BREAK_FIXED_MATERIAL,
    LIMIT_BREAK_GOLD_ROW_SIZE,
    LIMIT_BREAK_GOLD_ROWS,
    LIMIT_BREAK_GOLD_TABLE,
    LIMIT_BREAK_GOLD_TABLE_ORIGINAL_SHA256,
    LIMIT_BREAK_MAX_LEVEL,
    PatchOptions,
    apply_all_patches,
    apply_limit_break_cost_fixed,
    apply_limit_break_cost_tenth,
    apply_limit_break_step_10,
    inspect_limit_break_table,
    limit_break_step10_state,
    limit_break_step10_target,
)
from core.patch_inspector import (
    expected_feature_keys,
    inspect_apk,
    inspect_native_so,
    verify_report,
)
from fwt_patcher import build_parser, run_cli


def _rows(buf: bytes | bytearray) -> list[tuple[int, int, int, int, int, int]]:
    return [
        struct.unpack_from(
            "<6i", buf, LIMIT_BREAK_GOLD_TABLE + index * LIMIT_BREAK_GOLD_ROW_SIZE
        )
        for index in range(LIMIT_BREAK_GOLD_ROWS)
    ]


def test_limit_break_step10_target_snaps_to_tens() -> None:
    expected = {
        70: 80,
        72: 80,
        74: 80,
        76: 80,
        78: 80,
        80: 90,
        84: 90,
        90: 100,
        98: 100,
        100: 110,
        106: 110,
        110: 120,
        118: 120,
    }
    for before, after in expected.items():
        assert limit_break_step10_target(before) == after
    assert limit_break_step10_target(118) == LIMIT_BREAK_MAX_LEVEL


def test_step10_registered_and_idempotent(
    reference_buffers: tuple[bytes, bytes],
) -> None:
    assert EXPECTED_PATCH_COUNTS["limit_break_step_10"] == LIMIT_BREAK_GOLD_ROWS
    assert "limit_break_step_10" in IDEMPOTENT_PATCHES

    original, _ = reference_buffers
    stock = _rows(original)
    buf = bytearray(original)

    assert apply_limit_break_step_10(buf) == LIMIT_BREAK_GOLD_ROWS
    patched = _rows(buf)
    for orig_row, new_row in zip(stock, patched, strict=True):
        before, after, cat, item_code, mat, gold = new_row
        assert before == orig_row[0]
        assert after == limit_break_step10_target(before)
        assert (cat, item_code, mat, gold) == orig_row[2:]

    # Second invocation is a no-op.
    assert apply_limit_break_step_10(buf) == 0
    active, detail = limit_break_step10_state(buf)
    assert active is True
    assert "+10 to Lv120" in detail


@pytest.mark.parametrize(
    ("cost_fn", "expected_digest"),
    [
        (apply_limit_break_cost_fixed, LIMIT_BREAK_COST_FIXED_SHA256),
        (apply_limit_break_cost_tenth, LIMIT_BREAK_COST_TENTH_SHA256),
    ],
)
def test_step10_composes_in_both_orders_with_cost_patches(
    reference_buffers: tuple[bytes, bytes],
    cost_fn,
    expected_digest: str,
) -> None:
    original, _ = reference_buffers

    buf_a = bytearray(original)
    assert apply_limit_break_step_10(buf_a) == LIMIT_BREAK_GOLD_ROWS
    assert cost_fn(buf_a) == LIMIT_BREAK_GOLD_ROWS

    buf_b = bytearray(original)
    assert cost_fn(buf_b) == LIMIT_BREAK_GOLD_ROWS
    assert apply_limit_break_step_10(buf_b) == LIMIT_BREAK_GOLD_ROWS

    table_size = LIMIT_BREAK_GOLD_ROW_SIZE * LIMIT_BREAK_GOLD_ROWS
    table_a = bytes(buf_a[LIMIT_BREAK_GOLD_TABLE:LIMIT_BREAK_GOLD_TABLE + table_size])
    table_b = bytes(buf_b[LIMIT_BREAK_GOLD_TABLE:LIMIT_BREAK_GOLD_TABLE + table_size])
    assert table_a == table_b

    digest, step_mode = inspect_limit_break_table(table_a)
    assert step_mode == "step_10"
    assert digest == expected_digest


def test_step10_refuses_corrupted_or_mixed_table(
    reference_buffers: tuple[bytes, bytes],
) -> None:
    original, _ = reference_buffers

    bad_after = bytearray(original)
    struct.pack_into("<i", bad_after, LIMIT_BREAK_GOLD_TABLE + 4, 75)
    before = bytes(bad_after)
    with pytest.raises(ValueError, match="Unexpected limit break cost table"):
        apply_limit_break_step_10(bad_after)
    assert bytes(bad_after) == before

    bad_cat = bytearray(original)
    bad_cat[LIMIT_BREAK_GOLD_TABLE + 8] ^= 1
    before_cat = bytes(bad_cat)
    with pytest.raises(ValueError, match="Unexpected limit break cost table"):
        apply_limit_break_step_10(bad_cat)
    assert bytes(bad_cat) == before_cat


def test_apply_all_patches_and_inspector_so_checks(
    reference_buffers: tuple[bytes, bytes],
) -> None:
    so_bytes, dex_bytes = reference_buffers

    res = apply_all_patches(
        so_bytes,
        dex_bytes,
        PatchOptions(limit_break_step_10=True, limit_break_cost_fixed=True),
    )
    assert res.counts["limit_break_step_10"] == LIMIT_BREAK_GOLD_ROWS
    assert res.counts["limit_break_cost_fixed"] == LIMIT_BREAK_GOLD_ROWS

    reports = inspect_native_so(res.so_bytes)
    assert reports["limit_break_step_10"].active is True
    assert reports["limit_break_cost_fixed"].active is True
    assert reports["limit_break_cost_tenth"].active is False

    # Stock cost + step10 alone also reports accurately.
    res_only = apply_all_patches(
        so_bytes,
        dex_bytes,
        PatchOptions(limit_break_step_10=True),
    )
    table_size = LIMIT_BREAK_GOLD_ROW_SIZE * LIMIT_BREAK_GOLD_ROWS
    digest, mode = inspect_limit_break_table(
        res_only.so_bytes[LIMIT_BREAK_GOLD_TABLE:LIMIT_BREAK_GOLD_TABLE + table_size]
    )
    assert digest == LIMIT_BREAK_GOLD_TABLE_ORIGINAL_SHA256
    assert mode == "step_10"
    reports_only = inspect_native_so(res_only.so_bytes)
    assert reports_only["limit_break_step_10"].active is True
    assert reports_only["limit_break_cost_fixed"].active is False


def test_client_step10_unity3d_patching_unit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import UnityPy

    import core.apk_tooling as apk_tooling
    from core.apk_tooling import (
        LIMIT_BREAK_CLIENT_ASSET_PATH,
        _patch_resources_zip_file,
        inspect_limit_break_cost_assets,
        inspect_limit_break_step_assets,
        needs_resource_archive_patch,
    )

    assert needs_resource_archive_patch(PatchOptions(limit_break_step_10=True)) is True

    stock_rows = [
        {"_levelBefore": 70, "_levelAfter": 72, "_cost": 4_000_000, "_rewardValue02": 50},
        {"_levelBefore": 74, "_levelAfter": 76, "_cost": 5_600_000, "_rewardValue02": 80},
        {"_levelBefore": 118, "_levelAfter": 120, "_cost": 190_000_000, "_rewardValue02": 17380},
    ]
    fixed_cost_pairs = [(LIMIT_BREAK_FIXED_GOLD, LIMIT_BREAK_FIXED_MATERIAL)] * len(stock_rows)
    stock_cost_pairs = [(r["_cost"], r["_rewardValue02"]) for r in stock_rows]
    fake_profiles = {
        hashlib.sha256(repr(stock_cost_pairs).encode("ascii")).hexdigest(): "stock",
        hashlib.sha256(repr(fixed_cost_pairs).encode("ascii")).hexdigest(): "limit_break_cost_fixed",
    }
    monkeypatch.setattr(apk_tooling, "LIMIT_BREAK_CLIENT_PROFILE_SHA256", fake_profiles)

    def _encode_rows(rows: list[dict[str, int]]) -> bytes:
        return repr(rows).encode("utf-8")

    class _FakeObj:
        def __init__(self, state: dict[str, list[dict[str, int]]]) -> None:
            self.type = types.SimpleNamespace(name="MonoBehaviour")
            self._state = state

        def read_typetree(self) -> dict[str, list[dict[str, int]]]:
            return {"_data": [dict(r) for r in self._state["rows"]]}

        def save_typetree(self, tree: dict[str, list[dict[str, int]]]) -> None:
            self._state["rows"] = [dict(r) for r in tree["_data"]]

    class _FakeEnv:
        def __init__(self, clear: bytes) -> None:
            self._state = {"rows": ast.literal_eval(clear.decode("utf-8"))}
            self.objects = [_FakeObj(self._state)]
            self.file = types.SimpleNamespace(
                save=lambda: _encode_rows(self._state["rows"])
            )

    monkeypatch.setattr(apk_tooling, "_decrypt_datatable", lambda data: (data, "k", "v"))
    monkeypatch.setattr(apk_tooling, "_encrypt_datatable", lambda clear, _k, _v: clear)
    monkeypatch.setattr(UnityPy, "load", _FakeEnv)

    raw_res = tmp_path / "raw.zip"
    with zipfile.ZipFile(raw_res, "w") as zf:
        zf.writestr(LIMIT_BREAK_CLIENT_ASSET_PATH, _encode_rows(stock_rows))

    # 1) Standalone step10 keeps stock costs intact.
    work1 = tmp_path / "w1"
    work1.mkdir()
    step_zip, c1 = _patch_resources_zip_file(
        raw_res, PatchOptions(limit_break_step_10=True), work_dir=work1
    )
    assert c1 is not None
    with zipfile.ZipFile(step_zip, "r") as zf:
        step_ok, _ = inspect_limit_break_step_assets(zf)
        cost_prof, _ = inspect_limit_break_cost_assets(zf)
        saved_rows = ast.literal_eval(zf.read(LIMIT_BREAK_CLIENT_ASSET_PATH).decode("utf-8"))
    assert step_ok is True
    assert cost_prof == "stock"
    assert [(r["_levelBefore"], r["_levelAfter"]) for r in saved_rows] == [
        (70, 80),
        (74, 80),
        (118, 120),
    ]

    # 2) Second pass is idempotent and skips cleanly.
    work2 = tmp_path / "w2"
    work2.mkdir()
    logs: list[str] = []
    same_zip, c2 = _patch_resources_zip_file(
        step_zip, PatchOptions(limit_break_step_10=True), work_dir=work2, log_fn=logs.append
    )
    assert same_zip == step_zip
    assert c2 is None
    assert any("already matches" in msg for msg in logs)

    # 3) Applying fixed cost afterwards upgrades costs while keeping +10 steps.
    work3 = tmp_path / "w3"
    work3.mkdir()
    both_zip, c3 = _patch_resources_zip_file(
        step_zip,
        PatchOptions(limit_break_step_10=True, limit_break_cost_fixed=True),
        work_dir=work3,
    )
    assert c3 is not None
    with zipfile.ZipFile(both_zip, "r") as zf:
        step_ok, _ = inspect_limit_break_step_assets(zf)
        cost_prof, _ = inspect_limit_break_cost_assets(zf)
    assert step_ok is True
    assert cost_prof == "limit_break_cost_fixed"


@pytest.mark.integration
def test_inspector_reconciles_step10_with_reference_apk(
    tmp_path: Path, reference_buffers: tuple[bytes, bytes], reference_apk: Path
) -> None:
    from core.apk_tooling import (
        LIMIT_BREAK_CLIENT_ASSET_PATH,
        _patch_resources_zip_file,
    )

    so_bytes, dex_bytes = reference_buffers
    opts = PatchOptions(limit_break_step_10=True, limit_break_cost_fixed=True)
    res = apply_all_patches(so_bytes, dex_bytes, opts)

    raw_res = tmp_path / "raw_res.zip"
    with (
        zipfile.ZipFile(reference_apk, "r") as zf,
        zf.open("assets/fwt_resources_v1.zip") as inner_file,
        zipfile.ZipFile(inner_file, "r") as inner_zip,
        zipfile.ZipFile(raw_res, "w") as slim_res,
    ):
        slim_res.writestr(
            LIMIT_BREAK_CLIENT_ASSET_PATH,
            inner_zip.read(LIMIT_BREAK_CLIENT_ASSET_PATH),
        )

    # Stock client + patched SO must fail reconciliation.
    mismatched_apk = tmp_path / "mismatched.apk"
    with zipfile.ZipFile(mismatched_apk, "w") as zf:
        zf.writestr("lib/arm64-v8a/libfwt_local_server.so", res.so_bytes)
        zf.writestr("classes8.dex", res.dex_bytes)
        zf.writestr("assets/fwt_resources_v1.zip", raw_res.read_bytes())
    bad_report = inspect_apk(mismatched_apk)
    assert bad_report.features["limit_break_step_10"].active is False
    assert any("Limit Break +10 Levels" in p for p in verify_report(bad_report, opts))

    # Matching patched limitbreakcost.unity3d satisfies both step_10 and cost_fixed.
    patched_dir = tmp_path / "patched_res"
    patched_dir.mkdir()
    patched_res, contract = _patch_resources_zip_file(raw_res, opts, work_dir=patched_dir)
    assert contract is not None

    ok_apk = tmp_path / "ok.apk"
    with zipfile.ZipFile(ok_apk, "w") as zf:
        zf.writestr("lib/arm64-v8a/libfwt_local_server.so", res.so_bytes)
        zf.writestr("classes8.dex", res.dex_bytes)
        zf.writestr("assets/fwt_resources_v1.zip", patched_res.read_bytes())
    ok_report = inspect_apk(ok_apk)
    assert ok_report.features["limit_break_step_10"].active is True
    assert ok_report.features["limit_break_cost_fixed"].active is True


def test_cli_and_expected_keys(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    expected = expected_feature_keys(PatchOptions(limit_break_step_10=True))
    assert expected["limit_break_step_10"] == "Limit Break +10 Levels"

    dummy_in = tmp_path / "in.apk"
    dummy_in.write_bytes(b"PK")
    out_apk = tmp_path / "out.apk"
    called_opts: list[PatchOptions] = []

    class _Stop(RuntimeError):
        pass

    def _fake_repack(**kwargs):
        called_opts.append(kwargs["options"])
        raise _Stop

    monkeypatch.setattr("fwt_patcher.repack_and_sign_apk", _fake_repack)
    for argv in (
        ["--input", str(dummy_in), "--output", str(out_apk), "--all"],
        ["--input", str(dummy_in), "--output", str(out_apk), "--limit-break-step-10"],
    ):
        args = build_parser().parse_args(argv)
        assert run_cli(args) == 1
    assert len(called_opts) == 2
    assert called_opts[0].limit_break_step_10 is True
    assert called_opts[1].limit_break_step_10 is True
