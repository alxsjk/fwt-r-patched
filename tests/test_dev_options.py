"""Dev build scaffolding (phase 0).

These tests pin the three guarantees the dev build rests on:

1. nothing in the dev block can be enabled implicitly (``--all`` never touches it);
2. every instrumentation requires the master switch;
3. a dev build with no instrumentation is byte-identical to a release build.
"""

from __future__ import annotations

import pytest

from core.core_patches import (
    DEV_LOG_CAVE_SIZE,
    DEV_LOG_CAVE_VADDR,
    DEV_LOG_HOOK_VADDR,
    DEV_LOG_TAG_PREFIX,
    DEV_OUTPUT_SUFFIX,
    IMPLEMENTED_DEV_INSTRUMENTATION,
    DevOptions,
    PatchOptions,
    apply_all_patches,
    is_dev_output_path,
    seg_offset,
)


def test_dev_defaults_are_off():
    dev = PatchOptions().dev
    assert isinstance(dev, DevOptions)
    assert dev.enabled is False
    assert dev.instrumentation() == ()
    assert dev.any_instrumentation is False


def test_gameplay_options_never_enable_dev():
    """--all maps to gameplay flags only; the dev block must stay untouched."""
    opts = PatchOptions(
        campaign_gold=True,
        campaign_xp=True,
        english_localization=True,
        lan_redirect=True,
    )
    assert opts.dev.enabled is False
    assert opts.dev.instrumentation() == ()


def test_dev_output_path_marker() -> None:
    assert DEV_OUTPUT_SUFFIX == "-dev"
    assert DEV_LOG_TAG_PREFIX == "FWTR-DEV"
    assert is_dev_output_path("output/FWT-Reborn-Patched-dev-2.5.26.apk")
    assert is_dev_output_path("FWT-x-dev.apk")
    assert not is_dev_output_path("output/FWT-Reborn-Patched-2.5.26.apk")


def test_instrumentation_requires_master_switch():
    with pytest.raises(ValueError, match="master switch"):
        DevOptions(log_dispatch=True).validate()


def test_master_switch_alone_is_valid():
    DevOptions(enabled=True).validate()


def test_master_switch_with_instrumentation_is_valid():
    DevOptions(enabled=True, log_dispatch=True, log_body_limit=512).validate()


def test_negative_log_limit_is_rejected():
    with pytest.raises(ValueError, match="log_body_limit"):
        DevOptions(enabled=True, log_body_limit=-1).validate()


def test_every_instrumentation_field_is_listed():
    """Adding a field without adding it to _INSTRUMENTATION would hide it."""
    fields = {
        name
        for name in vars(DevOptions())
        if name
        not in {
            "enabled",
            "keep_version",  # manifest modifier, not instrumentation
            "log_body_limit",
            "log_commands",
        }
    }
    assert fields == set(DevOptions._INSTRUMENTATION)


def test_phase_one_implements_only_debuggable():
    """Keep this honest: a feature joins the set only when it is wired in."""
    assert frozenset(
        {
            "debuggable",
            "log_dispatch",
            "hit_counters",
            "build_marker",
            "handler_timing",
            "log_responses",
            "dev_endpoint",
        }
    ) == IMPLEMENTED_DEV_INSTRUMENTATION
    assert "state_snapshots" not in IMPLEMENTED_DEV_INSTRUMENTATION


def test_dev_build_is_byte_identical_to_release(reference_buffers):
    so_bytes, dex_bytes = reference_buffers
    release = apply_all_patches(so_bytes, dex_bytes, PatchOptions(campaign_gold=True))
    dev = apply_all_patches(
        so_bytes,
        dex_bytes,
        PatchOptions(campaign_gold=True, dev=DevOptions(enabled=True)),
    )
    assert dev.so_sha256 == release.so_sha256
    assert dev.dex_sha256 == release.dex_sha256


def test_pending_instrumentation_is_reported(reference_buffers):
    so_bytes, dex_bytes = reference_buffers
    result = apply_all_patches(
        so_bytes,
        dex_bytes,
        PatchOptions(
            campaign_gold=True,
            dev=DevOptions(enabled=True, state_snapshots=True, dev_endpoint=True),
        ),
    )
    joined = " ".join(result.warnings)
    assert "not implemented yet" in joined
    assert "state_snapshots" in joined
    assert "dev_endpoint" not in joined, "the DEV_DUMP endpoint is wired now"
    # Wired features must not be reported as pending.
    assert "log_dispatch" not in joined
    assert "hit_counters" not in joined
    assert "debuggable" not in joined


def test_apply_all_patches_rejects_instrumentation_without_master(reference_buffers):
    so_bytes, dex_bytes = reference_buffers
    with pytest.raises(ValueError, match="master switch"):
        apply_all_patches(
            so_bytes,
            dex_bytes,
            PatchOptions(campaign_gold=True, dev=DevOptions(log_dispatch=True)),
        )


def test_log_dispatch_touches_only_the_hook_and_the_cave(reference_buffers):
    """The dev instrumentation must be surgical: two regions, nothing else."""
    so_bytes, dex_bytes = reference_buffers
    release = apply_all_patches(so_bytes, dex_bytes, PatchOptions(campaign_gold=True))
    dev = apply_all_patches(
        so_bytes,
        dex_bytes,
        PatchOptions(campaign_gold=True, dev=DevOptions(enabled=True, log_dispatch=True)),
    )
    assert dev.counts["dev_log_dispatch"] == 1
    assert dev.so_sha256 != release.so_sha256
    assert dev.dex_sha256 == release.dex_sha256
    assert len(dev.so_bytes) == len(release.so_bytes)

    hook_offset = seg_offset(DEV_LOG_HOOK_VADDR)
    cave_start = seg_offset(DEV_LOG_CAVE_VADDR)
    cave_end = cave_start + DEV_LOG_CAVE_SIZE
    changed = [
        offset
        for offset in range(0, len(release.so_bytes), 4)
        if release.so_bytes[offset : offset + 4] != dev.so_bytes[offset : offset + 4]
    ]
    assert changed, "dev build did not change anything"
    for offset in changed:
        assert offset == hook_offset or cave_start <= offset < cave_end, (
            f"dev instrumentation touched 0x{offset + 0x4000:x}, outside the hook "
            "and the cave"
        )

def test_keep_version_leaves_the_manifest_version_untouched(reference_manifest):
    """`--dev-keep-version` exists because the game may validate the version string."""
    from core.apk_tooling import _patch_dev_manifest

    raw, resources_arsc = reference_manifest
    logs: list[str] = []

    kept = _patch_dev_manifest(
        raw, PatchOptions(dev=DevOptions(enabled=True, keep_version=True)), logs.append
    )
    assert kept == raw, "the manifest must stay byte-identical"
    assert any("kept as-is" in line for line in logs)

    suffixed = _patch_dev_manifest(
        raw, PatchOptions(dev=DevOptions(enabled=True)), logs.append
    )
    assert suffixed != raw
    assert DEV_OUTPUT_SUFFIX.encode("utf-16-le") in suffixed
    assert resources_arsc  # the fixture also ships resources.arsc for aapt2 checks


def test_dev_timing_only_records_dispatch_hook_and_resource_contract_logs(
    reference_buffers, monkeypatch: pytest.MonkeyPatch, tmp_path
):
    import io
    import zipfile

    from core.dex_smali import ResourceContract

    so_bytes, dex_bytes = reference_buffers
    timing_only = apply_all_patches(
        so_bytes,
        dex_bytes,
        PatchOptions(dev=DevOptions(enabled=True, handler_timing=True)),
    )
    assert "dev_dispatch_hook" in timing_only.counts
    assert "dev_build_marker" not in timing_only.counts

    second_pass = apply_all_patches(
        timing_only.so_bytes,
        timing_only.dex_bytes,
        PatchOptions(allow_unknown=True, dev=DevOptions(enabled=True, handler_timing=True)),
    )
    assert second_pass.counts["dev_dispatch_hook"] == 0

    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w") as zf:
        zf.writestr("sample.txt", b"ok")
    contract = ResourceContract.from_archive(zip_buf.getvalue())
    monkeypatch.setattr("core.core_patches.apply_bootstrap_dex", lambda *_a, **_kw: 0)

    logs: list[str] = []
    res_contract = apply_all_patches(
        so_bytes,
        dex_bytes,
        PatchOptions(crystal_skill_90_off=True),
        resource_contract=contract,
        apktool_jar=tmp_path / "apktool.jar",
        log_fn=logs.append,
    )
    assert any("Bundled resource contract updated:" in line for line in logs)
    assert not any("Bundled resource contract" in w for w in res_contract.warnings)


def test_dev_counters_standalone_and_log_commands_warning(reference_buffers):
    """--dev-counters instruments the dispatch hook alone and --dev-log-commands warns."""
    so_bytes, dex_bytes = reference_buffers
    counters_only = apply_all_patches(
        so_bytes,
        dex_bytes,
        PatchOptions(dev=DevOptions(enabled=True, hit_counters=True)),
    )
    assert counters_only.counts["dev_dispatch_hook"] == 1
    assert counters_only.so_bytes != so_bytes
    assert not any("not implemented yet" in w for w in counters_only.warnings)

    second_pass = apply_all_patches(
        counters_only.so_bytes,
        counters_only.dex_bytes,
        PatchOptions(allow_unknown=True, dev=DevOptions(enabled=True, hit_counters=True)),
    )
    assert second_pass.counts["dev_dispatch_hook"] == 0

    with_cmds = apply_all_patches(
        so_bytes,
        dex_bytes,
        PatchOptions(
            dev=DevOptions(enabled=True, log_dispatch=True, log_commands="GET_MY_INFO")
        ),
    )
    assert any("--dev-log-commands" in w and "offline" in w for w in with_cmds.warnings)
