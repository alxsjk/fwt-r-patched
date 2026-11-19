from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest

from core.apk_tooling import (
    SACRED_LANDS_SET_GROUP,
    AdbHelper,
    ToolPaths,
    _patch_equip_success_10_rows,
    _patch_equipment_percent_options_rows,
    _patch_rune_option_percent_rows,
    _restore_sacred_lands_select_rows,
    _restore_sacred_lands_set_rows,
    _rewrite_zip_entries,
    _rewrite_zip_entries_to_file,
    _version_key,
    describe_missing_packaging_tools,
    is_signature_file,
    needs_resource_archive_patch,
    repack_and_sign_apk,
)
from core.core_patches import PatchOptions, PatchResult
from core.dex_smali import ResourceContract


def test_describe_missing_packaging_tools_is_actionable():
    tools = ToolPaths(zipalign=None, apksigner="/sdk/apksigner", keytool=None)
    assert tools.missing_packaging_tools == ["zipalign", "keytool"]
    assert not tools.has_packaging_tools
    message = describe_missing_packaging_tools(tools)
    assert "zipalign, keytool" in message
    assert "not Python packages" in message
    assert "--check-tools" in message
    assert "README.md" in message

    ready = ToolPaths(
        zipalign="/sdk/zipalign",
        apksigner="/sdk/apksigner",
        keytool="/jdk/bin/keytool",
    )
    assert ready.has_packaging_tools
    assert ready.missing_packaging_tools == []
    assert describe_missing_packaging_tools(ready) == (
        "All required packaging tools are available."
    )


def test_version_key_sorts_numerically():
    paths = ["/sdk/build-tools/9.0.0/zipalign", "/sdk/build-tools/35.0.0/zipalign"]
    assert sorted(paths, key=_version_key)[-1].endswith("35.0.0/zipalign")


def test_signature_file_detection():
    assert is_signature_file("META-INF/MANIFEST.MF")
    assert is_signature_file("META-INF/CERT.SF")
    assert is_signature_file("META-INF/CERT.RSA")
    assert is_signature_file("META-INF/SIG-CUSTOM")
    assert not is_signature_file("META-INF/kotlin_module")
    assert not is_signature_file("lib/arm64-v8a/libfwt_local_server.so")


def test_rewrite_zip_entries_preserves_untouched_entries() -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("files/keep.bin", b"keep" * 200)
        archive.writestr("files/replace.bin", b"old")
    raw = buffer.getvalue()

    patched = _rewrite_zip_entries(raw, {"files/replace.bin": b"new data"})

    with zipfile.ZipFile(io.BytesIO(patched)) as archive:
        assert archive.read("files/keep.bin") == b"keep" * 200
        assert archive.read("files/replace.bin") == b"new data"
        assert archive.getinfo("files/replace.bin").compress_type == zipfile.ZIP_STORED
        assert len(archive.infolist()) == 2


def test_rewrite_zip_entries_rejects_missing_entry() -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("files/keep.bin", b"keep")
    with pytest.raises(ValueError, match="missing expected"):
        _rewrite_zip_entries(buffer.getvalue(), {"files/missing.bin": b"x"})


def test_rewrite_zip_entries_to_file_matches_the_bytes_wrapper(tmp_path: Path) -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("files/keep.bin", b"keep" * 200)
        archive.writestr("files/replace.bin", b"old")
    raw = buffer.getvalue()
    replacements = {"files/replace.bin": b"new data"}
    expected = _rewrite_zip_entries(raw, replacements)

    source = tmp_path / "source.zip"
    target = tmp_path / "target.zip"
    source.write_bytes(raw)
    _rewrite_zip_entries_to_file(source, replacements, target)

    assert target.read_bytes() == expected
    with zipfile.ZipFile(target) as archive:
        assert archive.read("files/keep.bin") == b"keep" * 200
        assert archive.read("files/replace.bin") == b"new data"


def test_resource_contract_from_archive_path_matches_bytes(tmp_path: Path) -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("files/a.bin", b"alpha")
        archive.writestr("files/b.bin", b"beta")
    raw = buffer.getvalue()
    path = tmp_path / "resources.zip"
    path.write_bytes(raw)

    assert ResourceContract.from_archive_path(path) == ResourceContract.from_archive(
        raw
    )


def test_restore_sacred_lands_set_rows_fixes_grade() -> None:
    tree = {
        "_data": [
            {"_setgroupid": SACRED_LANDS_SET_GROUP, "_itemGrade": 1},
            {"_setgroupid": SACRED_LANDS_SET_GROUP, "_itemGrade": 1},
            {"_setgroupid": 4027, "_itemGrade": 4},
        ]
    }
    assert _restore_sacred_lands_set_rows(tree) == 2
    assert [row["_itemGrade"] for row in tree["_data"][:2]] == [4, 4]
    assert _restore_sacred_lands_set_rows(tree) == 0


def test_restore_sacred_lands_set_rows_rejects_unknown_grade() -> None:
    tree = {"_data": [{"_setgroupid": SACRED_LANDS_SET_GROUP, "_itemGrade": 3}]}
    with pytest.raises(ValueError, match="unexpected Sacred Lands"):
        _restore_sacred_lands_set_rows(tree)


def test_restore_sacred_lands_select_rows_adds_both_tickets() -> None:
    tree = {"_data": [{"_equipListId": 10001, "_equipCode": 4101}]}
    assert _restore_sacred_lands_select_rows(tree) == 2
    added = {
        (row["_equipListId"], row["_equipCode"])
        for row in tree["_data"]
        if row["_equipCode"] == SACRED_LANDS_SET_GROUP
    }
    assert added == {(10001, SACRED_LANDS_SET_GROUP), (10004, SACRED_LANDS_SET_GROUP)}
    assert _restore_sacred_lands_select_rows(tree) == 0


def test_repack_rejects_identical_paths(tmp_path: Path):
    apk = tmp_path / "base.apk"
    apk.write_bytes(b"not really an apk")
    tools = ToolPaths(zipalign="zipalign", apksigner="apksigner", keytool="keytool")
    with pytest.raises(ValueError, match="identical"):
        repack_and_sign_apk(apk, apk, PatchOptions(), tools, tmp_path / "key.jks")


def test_repack_rejects_missing_resources_for_requested_patch(tmp_path: Path, monkeypatch):
    import core.apk_tooling as apk_tooling

    apk = tmp_path / "base.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("lib/arm64-v8a/libfwt_local_server.so", b"so")
        archive.writestr("classes8.dex", b"dex")
    monkeypatch.setattr(apk_tooling, "ensure_local_keystore", lambda *_args: None)
    tools = ToolPaths(zipalign="zipalign", apksigner="apksigner", keytool="keytool")
    with pytest.raises(RuntimeError, match="fwt_resources_v1.zip"):
        repack_and_sign_apk(
            apk, tmp_path / "out.apk", PatchOptions(event_discount=True),
            tools, tmp_path / "key.jks",
        )


def test_restore_rejects_invalid_json_without_device(tmp_path: Path):
    backup = tmp_path / "bad.json"
    backup.write_text("not json", encoding="utf-8")
    adb = AdbHelper("definitely-not-adb")
    ok, message = adb.restore_save("device", backup)
    assert ok is False
    assert "valid JSON" in message


def test_restore_rejects_non_object_json(tmp_path: Path):
    backup = tmp_path / "bad.json"
    backup.write_text("[1, 2, 3]", encoding="utf-8")
    ok, message = AdbHelper("adb").restore_save("device", backup)
    assert ok is False
    assert "savegame object" in message


def test_restore_rejects_unrelated_json_object(tmp_path: Path):
    backup = tmp_path / "config.json"
    backup.write_text('{"theme": "dark"}', encoding="utf-8")
    ok, message = AdbHelper("adb").restore_save("device", backup)
    assert ok is False
    assert "does not look like" in message


def test_restore_requires_an_installed_package(tmp_path: Path, monkeypatch):
    backup = tmp_path / "save.json"
    backup.write_text('{"lord": {}}', encoding="utf-8")
    adb = AdbHelper("adb")
    monkeypatch.setattr(adb, "package_state", lambda _device: "not_installed")
    ok, message = adb.restore_save("device", backup)
    assert ok is False
    assert "not installed" in message


def test_restore_refuses_an_unknown_package_state(tmp_path: Path, monkeypatch):
    backup = tmp_path / "save.json"
    backup.write_text('{"lord": {}}', encoding="utf-8")
    adb = AdbHelper("adb")
    monkeypatch.setattr(adb, "package_state", lambda _device: "unknown")
    ok, message = adb.restore_save("device", backup)
    assert ok is False
    assert "Could not determine" in message


def test_restore_creates_on_device_backup_and_uses_random_temp(tmp_path: Path, monkeypatch):
    backup = tmp_path / "save.json"
    backup.write_text('{"lord": {}}', encoding="utf-8")
    adb = AdbHelper("adb")
    calls: list[list[str]] = []

    def fake_run(args, timeout=30):
        calls.append(args)
        return 0, "", ""

    monkeypatch.setattr(adb, "package_state", lambda _device: "installed")
    monkeypatch.setattr(adb, "ensure_root", lambda _device: True)
    monkeypatch.setattr(adb, "_is_shell_root", lambda _device: True)
    monkeypatch.setattr(adb, "run_cmd", fake_run)

    ok, message = adb.restore_save("device", backup)
    assert ok is True, message
    remote_shell = " ".join(calls[-2])
    assert ".bak." in remote_shell
    assert "cmp -s" in remote_shell
    assert "fwt_restore_" in remote_shell
    assert "fwt_restore.json" not in remote_shell


def test_backup_failure_leaves_no_partial_file(tmp_path: Path, monkeypatch):
    output = tmp_path / "save.json"
    adb = AdbHelper("adb")

    def fail_run(_args, timeout=30):
        return 1, "", "offline"

    monkeypatch.setattr(adb, "ensure_root", lambda _device: False)
    monkeypatch.setattr(adb, "run_cmd", fail_run)
    ok, message = adb.backup_save("device", output)
    assert ok is False
    assert "Could not pull savegame" in message
    assert not output.exists()
    assert not output.with_name(output.name + ".part").exists()


def test_backup_rejects_json_that_restore_would_reject(tmp_path: Path, monkeypatch):
    output = tmp_path / "save.json"
    output.write_text('{"lord": {"old": true}}', encoding="utf-8")
    adb = AdbHelper("adb")

    def fake_run(args, timeout=30):
        if "pull" in args:
            Path(args[-1]).write_text("{}", encoding="utf-8")
            return 0, "", ""
        return 1, "", "unavailable"

    monkeypatch.setattr(adb, "ensure_root", lambda _device: False)
    monkeypatch.setattr(adb, "run_cmd", fake_run)
    ok, _message = adb.backup_save("device", output)
    assert not ok
    assert output.read_text(encoding="utf-8") == '{"lord": {"old": true}}'


def test_install_timeout_does_not_confirm_old_package(tmp_path: Path, monkeypatch):
    apk = tmp_path / "new.apk"
    apk.write_bytes(b"apk")
    adb = AdbHelper("adb")
    monkeypatch.setattr(adb, "run_cmd", lambda *args, **kwargs: (1, "", "timed out"))
    ok, message = adb.install_apk("device", apk)
    assert not ok
    assert "unknown" in message


def test_adb_helper_without_binary_reports_error():
    adb = AdbHelper("definitely-not-adb")
    code, out, err = adb.run_cmd(["devices"])
    assert code == 1
    assert "ADB" in err or "not" in err.lower() or out == ""


def test_needs_resource_archive_patch_includes_limit_break_cost_tenth() -> None:
    assert needs_resource_archive_patch(PatchOptions()) is False
    assert needs_resource_archive_patch(PatchOptions(campaign_gold=True)) is False
    assert (
        needs_resource_archive_patch(PatchOptions(limit_break_cost_tenth=True))
        is True
    )


def test_shop_inspector_detects_changed_localized_price(monkeypatch):
    import hashlib

    import core.apk_tooling as tooling

    def digest(values):
        return hashlib.sha256(repr(values).encode("ascii")).hexdigest()

    content_rows = [{"_content": 2, "_purchaseNum": 10, "_purchaselimittype": 1}]
    data_rows = [{"_category": 11, "_coinPrice": 3, "_friendPrice": -1,
                  "_itemCategory": 18, "_purchaselimittype": 255,
                  "_purchasecountperlimit": 255}]
    content_profile = (digest([10]), digest([10]))
    data_profile = (digest([3]), digest([(-1, None)]), digest([(255, 255)]))
    monkeypatch.setattr(tooling, "_SHOP_CONTENT_PROFILES", {"default": content_profile})
    monkeypatch.setattr(tooling, "_SHOP_DATA_PROFILES", {"default": data_profile})
    monkeypatch.setattr(tooling, "_SHOP_LIMIT_PROFILES", {
        ("shopcontentsdata", "default"): (digest([1]),),
        ("shopdata", "default"): (digest([255]),),
    })

    def read(_archive, name, *, label):
        rows = [dict(row) for row in (content_rows if "shopcontents" in name else data_rows)]
        if "shopcontentsdataenglish" in name:
            rows[0]["_purchaseNum"] = 11
        return rows, None

    monkeypatch.setattr(tooling, "_read_datatable_rows", read)
    with zipfile.ZipFile(io.BytesIO(), "w") as archive:
        reports = tooling.inspect_shop_assets(archive)
    assert not reports["event_discount"][0]
    assert not reports["campaign_shop_discount"][0]
    assert reports["event_gene_unlimited"][0]
    assert reports["event_limits_daily"][0]


def test_repack_patches_resources_for_limit_break_cost_tenth_alone(
    tmp_path: Path, monkeypatch
) -> None:
    import shutil

    import core.apk_tooling as apk_tooling

    raw_res_buf = io.BytesIO()
    with zipfile.ZipFile(raw_res_buf, "w") as res_zip:
        res_zip.writestr("files/Resources/datatable/limitbreakcost.unity3d", b"orig")
    raw_res_bytes = raw_res_buf.getvalue()

    patched_res_buf = io.BytesIO()
    with zipfile.ZipFile(patched_res_buf, "w") as res_zip:
        res_zip.writestr("files/Resources/datatable/limitbreakcost.unity3d", b"div10")
    patched_res_bytes = patched_res_buf.getvalue()
    expected_contract = ResourceContract.from_archive(patched_res_bytes)

    in_apk = tmp_path / "base.apk"
    out_apk = tmp_path / "out.apk"
    keystore = tmp_path / "test.jks"
    with zipfile.ZipFile(in_apk, "w") as zf:
        zf.writestr("lib/arm64-v8a/libfwt_local_server.so", b"so")
        zf.writestr("classes8.dex", b"dex")
        zf.writestr("assets/fwt_resources_v1.zip", raw_res_bytes)

    tools = ToolPaths(
        zipalign="/sdk/zipalign",
        apksigner="/sdk/apksigner",
        keytool="/jdk/keytool",
    )
    patch_calls: list[bool] = []
    seen_contracts: list[ResourceContract | None] = []

    def _fake_patch_res(
        _raw_zip: Path,
        options: PatchOptions,
        *,
        work_dir: Path,
        log_fn=None,
    ) -> tuple[Path, ResourceContract | None]:
        del log_fn
        patch_calls.append(options.limit_break_cost_tenth)
        out_res = work_dir / "fwt_resources_patched.zip"
        out_res.write_bytes(patched_res_bytes)
        return out_res, expected_contract

    def _fake_apply(
        _so_bytes: bytes,
        _dex_bytes: bytes,
        _options: PatchOptions,
        *,
        resource_contract: ResourceContract | None = None,
        apktool_jar=None,
        log_fn=None,
    ) -> PatchResult:
        del apktool_jar, log_fn
        seen_contracts.append(resource_contract)
        return PatchResult(
            so_bytes=b"so_patched",
            dex_bytes=b"dex_patched",
            so_sha256="a" * 64,
            dex_sha256="b" * 64,
        )

    def _fake_run_tool(args: list[str], label: str, timeout: int = 300) -> str:
        del timeout
        if label == "zipalign":
            shutil.copyfile(args[-2], args[-1])
        elif label == "apksigner":
            out_idx = args.index("--out") + 1
            shutil.copyfile(args[-1], args[out_idx])
        return ""

    monkeypatch.setattr(apk_tooling, "ensure_local_keystore", lambda *_args: None)
    monkeypatch.setattr(apk_tooling, "ensure_apktool_jar", lambda *_args: tmp_path / "apktool.jar")
    monkeypatch.setattr(apk_tooling, "_patch_resources_zip_file", _fake_patch_res)
    monkeypatch.setattr(apk_tooling, "apply_all_patches", _fake_apply)
    monkeypatch.setattr(apk_tooling, "_run_tool", _fake_run_tool)

    repack_and_sign_apk(
        in_apk,
        out_apk,
        PatchOptions(limit_break_cost_tenth=True),
        tools,
        keystore,
    )

    assert patch_calls == [True]
    assert seen_contracts == [expected_contract]
    with zipfile.ZipFile(out_apk, "r") as zf:
        assert zf.read("assets/fwt_resources_v1.zip") == patched_res_bytes


def test_inspect_limit_break_cost_assets_profiles(tmp_path: Path, reference_apk: Path) -> None:
    from core.apk_tooling import (
        LIMIT_BREAK_CLIENT_ASSET_PATH,
        _patch_resources_zip_file,
        inspect_limit_break_cost_assets,
    )

    raw_res = tmp_path / "raw_resources.zip"
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

    with zipfile.ZipFile(raw_res, "r") as archive:
        profile, _details = inspect_limit_break_cost_assets(archive)
    assert profile == "stock"

    for flag_name, flag_opts in (
        ("limit_break_cost_tenth", PatchOptions(limit_break_cost_tenth=True)),
    ):
        work_dir = tmp_path / flag_name
        work_dir.mkdir()
        patched_zip, contract = _patch_resources_zip_file(
            raw_res,
            flag_opts,
            work_dir=work_dir,
        )
        assert contract is not None
        with zipfile.ZipFile(patched_zip, "r") as archive:
            profile, _details = inspect_limit_break_cost_assets(archive)
        assert profile == flag_name

def test_inspect_limit_break_cost_assets_missing(tmp_path: Path) -> None:
    from core.apk_tooling import inspect_limit_break_cost_assets

    empty_zip = tmp_path / "empty.zip"
    with zipfile.ZipFile(empty_zip, "w"):
        pass
    with zipfile.ZipFile(empty_zip, "r") as archive:
        missing_profile, msg = inspect_limit_break_cost_assets(archive)
    assert missing_profile is None
    assert "not found" in msg


@pytest.mark.integration
def test_patch_resources_limit_break_is_idempotent_and_rejects_conflicts(
    tmp_path: Path, reference_apk: Path,
) -> None:
    from core.apk_tooling import (
        LIMIT_BREAK_CLIENT_ASSET_PATH,
        _patch_resources_zip_file,
        inspect_limit_break_cost_assets,
    )

    raw_res = tmp_path / "raw_resources.zip"
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

    work1 = tmp_path / "pass1"
    work1.mkdir()
    logs1: list[str] = []
    patched_zip, contract1 = _patch_resources_zip_file(
        raw_res,
        PatchOptions(limit_break_cost_tenth=True),
        work_dir=work1,
        log_fn=logs1.append,
    )
    assert contract1 is not None

    work2 = tmp_path / "pass2"
    work2.mkdir()
    logs2: list[str] = []
    second_zip, contract2 = _patch_resources_zip_file(
        patched_zip,
        PatchOptions(limit_break_cost_tenth=True),
        work_dir=work2,
        log_fn=logs2.append,
    )
    assert contract2 is None
    assert second_zip == patched_zip
    assert any("already matches limit_break_cost_tenth" in msg for msg in logs2)
    with zipfile.ZipFile(patched_zip, "r") as archive:
        profile, _details = inspect_limit_break_cost_assets(archive)
    assert profile == "limit_break_cost_tenth"



def test_patch_resources_fails_closed_when_optional_deps_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import builtins

    from core.apk_tooling import _patch_resources_zip_file

    raw_res = tmp_path / "res.zip"
    with zipfile.ZipFile(raw_res, "w"):
        pass

    real_import = builtins.__import__

    def _block_unitypy(name: str, *args, **kwargs):
        if name == "UnityPy":
            raise ImportError("simulated missing UnityPy")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _block_unitypy)

    with pytest.raises(RuntimeError, match="requires 'UnityPy' and 'cryptography'"):
        _patch_resources_zip_file(
            raw_res,
            PatchOptions(limit_break_cost_tenth=True),
            work_dir=tmp_path,
        )

    out_path, contract = _patch_resources_zip_file(
        raw_res,
        PatchOptions(),
        work_dir=tmp_path,
    )
    assert out_path == raw_res
    assert contract is None


def test_patch_resources_limit_break_unit_idempotent_and_conflict(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import hashlib
    import types

    import UnityPy

    import core.apk_tooling as apk_tooling
    from core.apk_tooling import LIMIT_BREAK_CLIENT_ASSET_PATH, _patch_resources_zip_file

    stock_rows = [{"_cost": 100, "_rewardValue02": 10}]
    tenth_rows = [{"_cost": 10, "_rewardValue02": 1}]
    fake_profiles = {
        hashlib.sha256(repr([(100, 10)]).encode("ascii")).hexdigest(): "stock",
        hashlib.sha256(repr([(10, 1)]).encode("ascii")).hexdigest(): "limit_break_cost_tenth",
        hashlib.sha256(repr([(50, 5)]).encode("ascii")).hexdigest(): "limit_break_cost_half",
    }
    monkeypatch.setattr(apk_tooling, "LIMIT_BREAK_CLIENT_PROFILE_SHA256", fake_profiles)

    def _encode_rows(rows: list[dict[str, int]]) -> bytes:
        return repr(rows).encode("utf-8")

    def _fake_decrypt(data: bytes) -> tuple[bytes, str, str]:
        return data, "k", "v"

    def _fake_encrypt(clear: bytes, _k: str, _v: str) -> bytes:
        return clear

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
            import ast

            self._state = {"rows": ast.literal_eval(clear.decode("utf-8"))}
            self.objects = [_FakeObj(self._state)]
            self.file = types.SimpleNamespace(
                save=lambda: _encode_rows(self._state["rows"])
            )

    monkeypatch.setattr(apk_tooling, "_decrypt_datatable", _fake_decrypt)
    monkeypatch.setattr(apk_tooling, "_encrypt_datatable", _fake_encrypt)
    monkeypatch.setattr(UnityPy, "load", _FakeEnv)

    raw_res = tmp_path / "raw_unit.zip"
    with zipfile.ZipFile(raw_res, "w") as zf:
        zf.writestr(LIMIT_BREAK_CLIENT_ASSET_PATH, _encode_rows(stock_rows))

    work1 = tmp_path / "u1"
    work1.mkdir()
    patched_zip, contract1 = _patch_resources_zip_file(
        raw_res,
        PatchOptions(limit_break_cost_tenth=True),
        work_dir=work1,
    )
    assert contract1 is not None
    with zipfile.ZipFile(patched_zip, "r") as zf:
        assert zf.read(LIMIT_BREAK_CLIENT_ASSET_PATH) == _encode_rows(tenth_rows)

    work2 = tmp_path / "u2"
    work2.mkdir()
    second_zip, contract2 = _patch_resources_zip_file(
        patched_zip,
        PatchOptions(limit_break_cost_tenth=True),
        work_dir=work2,
    )
    assert second_zip == patched_zip
    assert contract2 is None

    # A table already carrying another profile must be refused, not stacked.
    half_zip = tmp_path / "half_unit.zip"
    with zipfile.ZipFile(half_zip, "w") as zf:
        zf.writestr(LIMIT_BREAK_CLIENT_ASSET_PATH, _encode_rows([{"_cost": 50, "_rewardValue02": 5}]))
    work3 = tmp_path / "u3"
    work3.mkdir()
    with pytest.raises(RuntimeError, match="conflicting profile 'limit_break_cost_half'"):
        _patch_resources_zip_file(
            half_zip,
            PatchOptions(limit_break_cost_tenth=True),
            work_dir=work3,
        )


def test_datatable_crypto_keys_validates_env_and_ignores_placeholders(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from core.apk_tooling import _datatable_crypto_keys, _encrypt_datatable

    # Missing or CHANGE_ME placeholders from .env.example must fail explicitly.
    monkeypatch.setenv("FWT_DATATABLE_CRYPT_KEY", "CHANGE_ME_32_BYTES")
    monkeypatch.setenv("FWT_DATATABLE_CRYPT_IV", "CHANGE_ME_16_BYTES")
    monkeypatch.setenv("FWT_DATATABLE_CRYPT_KEY_REVERSED", "  ")
    monkeypatch.setenv("FWT_DATATABLE_CRYPT_IV_REVERSED", "")
    with pytest.raises(ValueError, match="Missing datatable AES credentials"):
        _datatable_crypto_keys()

    # Custom forward key/IV without explicit *_REVERSED derives its reversed pair.
    custom_key = "0123456789abcdef0123456789abcdef"
    custom_iv = "0123456789abcdef"
    monkeypatch.setenv("FWT_DATATABLE_CRYPT_KEY", custom_key)
    monkeypatch.setenv("FWT_DATATABLE_CRYPT_IV", custom_iv)
    custom_pairs = _datatable_crypto_keys()
    assert custom_pairs == (
        (custom_key[::-1], custom_iv[::-1]),
        (custom_key, custom_iv),
    )

    # Malformed lengths fail explicitly with the env variable name (never the value).
    monkeypatch.setenv("FWT_DATATABLE_CRYPT_KEY", "bad-secret-len")
    with pytest.raises(ValueError, match="FWT_DATATABLE_CRYPT_KEY") as exc:
        _datatable_crypto_keys()
    assert "bad-secret-len" not in str(exc.value)

    monkeypatch.setenv("FWT_DATATABLE_CRYPT_KEY", custom_key)
    monkeypatch.setenv("FWT_DATATABLE_CRYPT_IV", "short-iv")
    with pytest.raises(ValueError, match="FWT_DATATABLE_CRYPT_IV") as iv_exc:
        _datatable_crypto_keys()
    assert "short-iv" not in str(iv_exc.value)

    with pytest.raises(ValueError, match="Invalid datatable AES key/IV length"):
        _encrypt_datatable(b"UnityFS", "bad", "short")


def test_backup_save_prefers_rooted_adb_pull_over_external_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from core.apk_tooling import EXTERNAL_SAVE_BACKUP, REMOTE_SAVE_PATH, AdbHelper

    output = tmp_path / "save.json"
    adb = AdbHelper("adb")
    rooted = False
    pulled_paths: list[str] = []

    def fake_ensure_root(_device: str) -> bool:
        nonlocal rooted
        rooted = True
        return True

    def fake_run(args: list[str], timeout: int = 30) -> tuple[int, str, str]:
        if args[2] == "pull":
            remote, local = args[3], Path(args[4])
            pulled_paths.append(remote)
            if remote == REMOTE_SAVE_PATH and rooted:
                local.write_text('{"lord": {"level": 99}}', encoding="utf-8")
                return 0, "", ""
            if remote == EXTERNAL_SAVE_BACKUP:
                local.write_text('{"lord": {"level": 1}}', encoding="utf-8")
                return 0, "", ""
        return 1, "", "permission denied"

    monkeypatch.setattr(adb, "ensure_root", fake_ensure_root)
    monkeypatch.setattr(adb, "run_cmd", fake_run)

    ok, message = adb.backup_save("device", output)
    assert ok is True
    assert "Save successfully backed up" in message
    assert output.read_text(encoding="utf-8") == '{"lord": {"level": 99}}'
    assert pulled_paths == [REMOTE_SAVE_PATH, REMOTE_SAVE_PATH]


def test_backup_save_prefers_su_and_run_as_before_external_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from core.apk_tooling import EXTERNAL_SAVE_BACKUP, REMOTE_SAVE_PATH, AdbHelper

    output = tmp_path / "save.json"
    adb = AdbHelper("adb")
    calls: list[list[str]] = []

    def fake_run(args: list[str], timeout: int = 30) -> tuple[int, str, str]:
        calls.append(args[2:])
        if args[2] == "shell" and args[3].startswith("su -c "):
            return 0, '{"lord": {"level": 50}}', ""
        if args[2] == "pull" and args[3] == EXTERNAL_SAVE_BACKUP:
            Path(args[4]).write_text('{"lord": {"level": 1}}', encoding="utf-8")
            return 0, "", ""
        return 1, "", "denied"

    monkeypatch.setattr(adb, "ensure_root", lambda _device: False)
    monkeypatch.setattr(adb, "run_cmd", fake_run)

    ok, message = adb.backup_save("device", output)
    assert ok is True
    assert "via su" in message
    assert output.read_text(encoding="utf-8") == '{"lord": {"level": 50}}'
    assert [c[0] for c in calls] == ["pull", "shell"]
    assert EXTERNAL_SAVE_BACKUP not in [c[1] for c in calls]

    # When su fails, run-as on private sandbox still takes precedence over external copy.
    output_run_as = tmp_path / "save_run_as.json"
    calls.clear()

    def fake_run_as(args: list[str], timeout: int = 30) -> tuple[int, str, str]:
        calls.append(args[2:])
        if args[2] == "shell" and args[3].startswith("run-as "):
            return 0, '{"lord": {"level": 77}}', ""
        if args[2] == "pull" and args[3] == EXTERNAL_SAVE_BACKUP:
            Path(args[4]).write_text('{"lord": {"level": 1}}', encoding="utf-8")
            return 0, "", ""
        return 1, "", "denied"

    monkeypatch.setattr(adb, "run_cmd", fake_run_as)
    ok2, msg2 = adb.backup_save("device", output_run_as)
    assert ok2 is True
    assert "via run-as" in msg2
    assert output_run_as.read_text(encoding="utf-8") == '{"lord": {"level": 77}}'
    assert all(c[1] != EXTERNAL_SAVE_BACKUP for c in calls)
    assert REMOTE_SAVE_PATH in calls[0][1]


def test_backup_save_uses_external_copy_only_as_last_resort(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from core.apk_tooling import EXTERNAL_SAVE_BACKUP, REMOTE_SAVE_PATH, AdbHelper

    output = tmp_path / "save_ext.json"
    adb = AdbHelper("adb")
    order: list[str] = []

    def fake_run(args: list[str], timeout: int = 30) -> tuple[int, str, str]:
        if args[2] == "pull":
            order.append(f"pull:{args[3]}")
            if args[3] == EXTERNAL_SAVE_BACKUP:
                Path(args[4]).write_text('{"lord": {"level": 12}}', encoding="utf-8")
                return 0, "", ""
            return 1, "", "denied"
        order.append(f"shell:{args[3].split()[0]}")
        return 1, "", "failed"

    monkeypatch.setattr(adb, "ensure_root", lambda _device: False)
    monkeypatch.setattr(adb, "run_cmd", fake_run)

    ok, message = adb.backup_save("device", output)
    assert ok is True
    assert "game-generated copy" in message
    assert output.read_text(encoding="utf-8") == '{"lord": {"level": 12}}'
    assert order[-1] == f"pull:{EXTERNAL_SAVE_BACKUP}"
    assert order[:-1] == [
        f"pull:{REMOTE_SAVE_PATH}",
        "shell:su",
        "shell:run-as",
    ]


def test_equipment_percent_options_zeroes_only_flat_weights():
    rows = [
        {"_valueType": 1, "_weight1": 100, "_weight2": 0, "_weight3": 300,
         "_weight4": 0, "_weight5": 0, "_weight6": 0},
        {"_valueType": 2, "_weight1": 100, "_weight2": 0, "_weight3": 300,
         "_weight4": 0, "_weight5": 0, "_weight6": 0},
        {"_valueType": 4, "_weight1": 0, "_weight2": 200, "_weight3": 0,
         "_weight4": 0, "_weight5": 0, "_weight6": 0},
    ]
    assert _patch_equipment_percent_options_rows(rows) == 2
    assert rows[0]["_weight1"] == 0
    assert rows[0]["_weight3"] == 0
    assert rows[1]["_weight1"] == 100
    assert rows[1]["_weight3"] == 300
    assert rows[2]["_weight2"] == 200
    assert _patch_equipment_percent_options_rows(rows) == 0


def test_equipment_percent_options_requires_a_percent_pool():
    rows = [{"_valueType": 1, "_weight1": 100, "_weight2": 0, "_weight3": 0,
             "_weight4": 0, "_weight5": 0, "_weight6": 0}]
    with pytest.raises(ValueError, match="no percentage rows"):
        _patch_equipment_percent_options_rows(rows)


def test_rune_option_percent_rows_zero_only_flat_weights():
    rows = [
        {"_valueType": 1, "_weight": 23000},
        {"_valueType": 2, "_weight": 20000},
        {"_valueType": 4, "_weight": 15000},
        {"_valueType": 1, "_weight": 0},
    ]
    assert _patch_rune_option_percent_rows(rows) == 1
    assert rows[0]["_weight"] == 0
    assert rows[1]["_weight"] == 20000
    assert rows[2]["_weight"] == 15000
    assert _patch_rune_option_percent_rows(rows) == 0


def test_rune_option_percent_rows_requires_a_percent_pool():
    rows = [{"_valueType": 1, "_weight": 23000}]
    with pytest.raises(ValueError, match="no percentage rows"):
        _patch_rune_option_percent_rows(rows)


def test_equipment_upgrade_10_guarantee_sets_the_plus_nine_row():
    rows = [
        {"_baseEquipEnchant": 8, "_successProb1": 30000, "_successProb2": 30000,
         "_successProb3": 30000, "_successProb4": 30000, "_successProb5": 30000,
         "_successProb6": 30000},
        {"_baseEquipEnchant": 9, "_successProb1": 38000, "_successProb2": 38000,
         "_successProb3": 38000, "_successProb4": 38000, "_successProb5": 38000,
         "_successProb6": 38000},
    ]
    assert _patch_equip_success_10_rows(rows) == 6
    assert rows[0]["_successProb1"] == 30000
    assert all(rows[1][f"_successProb{i}"] == 100000 for i in range(1, 7))
    assert _patch_equip_success_10_rows(rows) == 0


def test_equipment_upgrade_10_guarantee_requires_the_plus_nine_row():
    with pytest.raises(ValueError, match=r"expected one \+9 success row"):
        _patch_equip_success_10_rows([{"_baseEquipEnchant": 8}])


def test_new_equipment_asset_options_request_the_resource_archive():
    assert needs_resource_archive_patch(
        PatchOptions(equipment_percent_options=True)
    )
    assert needs_resource_archive_patch(
        PatchOptions(equipment_upgrade_10_guarantee=True)
    )
    assert needs_resource_archive_patch(
        PatchOptions(rune_upgrade_discount=True)
    )


def test_decrypt_datatable_fails_closed_on_invalid_payload(
    monkeypatch: pytest.MonkeyPatch,
):
    from core.apk_tooling import _decrypt_datatable

    with pytest.raises(ValueError, match="Missing datatable AES credentials"):
        _decrypt_datatable(b"not-a-valid-unityfs-bundle")

    monkeypatch.setenv("FWT_DATATABLE_CRYPT_KEY", "0123456789abcdef0123456789abcdef")
    monkeypatch.setenv("FWT_DATATABLE_CRYPT_IV", "0123456789abcdef")

    with pytest.raises(ValueError, match="Failed to decrypt UnityFS"):
        _decrypt_datatable(b"not-a-valid-unityfs-bundle")

    clear, key, iv = _decrypt_datatable(b"UnityFS\x00unencrypted-test")
    assert clear == b"UnityFS\x00unencrypted-test"
    assert key == "fedcba9876543210fedcba9876543210"
    assert iv == "fedcba9876543210"


def test_restore_save_allows_su_root_when_adb_root_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backup = tmp_path / "save.json"
    backup.write_text('{"lord": {}}', encoding="utf-8")
    adb = AdbHelper("adb")
    calls: list[list[str]] = []

    def fake_run(args: list[str], timeout: int = 30) -> tuple[int, str, str]:
        del timeout
        calls.append(args)
        if args[2] == "shell" and args[3] == "su -c id":
            return 0, "uid=0(root) gid=0(root)", ""
        return 0, "", ""

    monkeypatch.setattr(adb, "package_state", lambda _device: "installed")
    monkeypatch.setattr(adb, "ensure_root", lambda _device: False)
    monkeypatch.setattr(adb, "_is_shell_root", lambda _device: False)
    monkeypatch.setattr(adb, "run_cmd", fake_run)

    ok, message = adb.restore_save("device", backup)
    assert ok is True, message
    assert any(c[2] == "shell" and c[3].startswith("su -c 'set -e;") for c in calls)


def test_ensure_apktool_jar_rejects_mismatched_configured_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from core.dex_smali import ensure_apktool_jar

    fake_jar = tmp_path / "bad_apktool.jar"
    fake_jar.write_bytes(b"tampered")
    monkeypatch.setenv("FWT_APKTOOL_JAR", str(fake_jar))
    with pytest.raises(RuntimeError, match="unexpected SHA-256"):
        ensure_apktool_jar()


def test_backup_save_accepts_utf8_bom_from_shell_cat(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from core.apk_tooling import AdbHelper

    output = tmp_path / "save_bom.json"
    adb = AdbHelper("adb")

    def fake_run(args: list[str], timeout: int = 30) -> tuple[int, str, str]:
        del timeout
        if args[2] == "shell" and args[3].startswith("su -c "):
            return 0, '\ufeff{"lord": {"level": 60}}', ""
        return 1, "", "denied"

    monkeypatch.setattr(adb, "ensure_root", lambda _device: False)
    monkeypatch.setattr(adb, "run_cmd", fake_run)

    ok, message = adb.backup_save("device", output)
    assert ok is True, message
    assert output.read_text(encoding="utf-8") == '{"lord": {"level": 60}}'


def test_tool_env_injects_keystore_password_only_when_requested(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from core.apk_tooling import _tool_env

    monkeypatch.delenv("FWT_KEYSTORE_PASS", raising=False)
    assert "FWT_KEYSTORE_PASS" not in _tool_env(include_keystore_pass=False)
    assert "FWT_KEYSTORE_PASS" in _tool_env(include_keystore_pass=True)

    monkeypatch.setenv("FWT_KEYSTORE_PASS", "custom-secret")
    assert "FWT_KEYSTORE_PASS" not in _tool_env(include_keystore_pass=False)
    assert _tool_env(include_keystore_pass=True)["FWT_KEYSTORE_PASS"] == "custom-secret"
