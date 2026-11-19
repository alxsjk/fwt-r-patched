"""Phase 2: the static dead-code map.

Marked ``slow`` because it disassembles the whole native library with capstone in
detail mode (a few minutes on the build host); run it with
``python -m pytest -m slow tests/test_dead_code_map.py``.

The map must keep agreeing with the caves the project already ships: those were
carved because they are unused, so a map that calls them "reachable" is a map
that would have blocked the very caves that work.
"""

from __future__ import annotations

import pytest

from core.core_patches import seg_offset
from tools.dead_code_map import (
    DEFAULT_PROFILES,
    KNOWN_CAVE_RANGES,
    build_map,
)

pytestmark = [pytest.mark.slow, pytest.mark.integration]


@pytest.fixture(scope="module")
def dead_code_report(reference_buffers):
    so_bytes, _dex = reference_buffers
    return build_map(so_bytes, 96, DEFAULT_PROFILES)


def test_report_has_the_three_profiles(dead_code_report):
    assert set(dead_code_report["profiles"]) == set(DEFAULT_PROFILES)


def test_map_found_candidates(dead_code_report):
    conservative = dead_code_report["profiles"]["conservative"]
    assert conservative["candidate_bytes"] > 0
    # Assuming the demangler is dead only adds candidates; it never removes them.
    demangler = dead_code_report["profiles"]["demangler-only"]
    assert demangler["candidate_bytes"] >= conservative["candidate_bytes"]
    assert demangler["matched"]


def test_candidates_are_aligned_and_sized(dead_code_report):
    total = 0
    for profile in dead_code_report["profiles"].values():
        for candidate in profile["candidates"]:
            assert candidate["address"] % 4 == 0
            assert candidate["size"] >= 96
            total += 1
    assert total > 0


def test_known_caves_are_explained(dead_code_report):
    labels = {entry["label"] for entry in dead_code_report["known_caves"]}
    assert labels == {label for label, _start, _end in KNOWN_CAVE_RANGES}
    for entry in dead_code_report["known_caves"]:
        assert entry["contains"] != "outside any sized function"


def test_demangler_cave_is_visible(dead_code_report):
    """0xb33314 (a cave already shipped) sits inside a function the map sees."""
    entry = next(
        item for item in dead_code_report["known_caves"] if "campaign" in item["label"]
    )
    assert "itanium_demangle" in entry["contains"]


def test_shipped_caves_sit_inside_assumed_dead_candidates(dead_code_report):
    """The precedent: each shipped cave is explained by a profile.

    The campaign caves live in a ``demangler-only`` candidate. The ``FLAN`` shim
    overwrites ``fwt_run_http_server``, which is **exported** (so it can never be a
    candidate) and is instead covered by the ``lan-mode`` *pattern* — which is
    legitimate only because LAN builds ``NOP`` the server spawn sites.
    """
    demangler = dead_code_report["profiles"]["demangler-only"]["candidates"]
    lan_patterns = dead_code_report["profiles"]["lan-mode"]["matched"]

    def covering(candidates, address):
        return [
            item
            for item in candidates
            if item["address"] <= address < item["address"] + item["size"]
        ]

    campaign_cave = next(
        entry for entry in dead_code_report["known_caves"] if "campaign" in entry["label"]
    )
    flan_cave = next(
        entry for entry in dead_code_report["known_caves"] if "lan_redirect" in entry["label"]
    )
    campaign_start = int(campaign_cave["range"].split("..")[0], 16)

    assert covering(demangler, campaign_start), "demangler cave not explained by the map"
    assert "fwt_run_http_server" in flan_cave["contains"]
    assert "fwt_run_http_server" in lan_patterns


def test_candidate_addresses_are_inside_text(dead_code_report):
    text = dead_code_report["text"]
    end = text["start"] + text["size"]
    for profile in dead_code_report["profiles"].values():
        for candidate in profile["candidates"]:
            assert text["start"] <= candidate["address"] < end
            assert candidate["address"] + candidate["size"] <= end + 64


def test_trap_helper_targets_a_mapped_segment(dead_code_report):
    """Every candidate must be patchable: seg_offset has to resolve it."""
    for candidate in dead_code_report["profiles"]["demangler-only"]["candidates"]:
        offset = seg_offset(candidate["address"])
        assert offset >= 0
