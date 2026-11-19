"""Dev-build log parser (phase 7).

The parser is the only thing standing between "logcat text" and "data", so the tests
pin the formats it accepts, the counter-gap detection (logd drops lines) and the
request/timing pairing rules.
"""

from __future__ import annotations

import json

import pytest

from tools.dev_log_parse import (
    Record,
    main,
    parse_capture,
    parse_line,
    summarize,
)

THREADTIME = '11-11 22:00:24.856  15837 15950 I FWTR-DEV-v2.5.26: 1 {"CMD":"GET_SHOP_LIST"}'
TIME = '11-11 22:21:41.416 I/FWTR-DEV-v2.5.26(16715): 1 {"CMD":"GET_SHOP_LIST"}'
MARKER = (
    "11-11 22:00:24.856  15837 15950 I FWTR-DEV-BUILD: FWTR-DEV v2.5.26 "
    "fp=65a95d1c n=37 flags=build_marker,handler_timing,hit_counters,log_dispatch"
)


def test_threadtime_line_is_parsed():
    record = parse_line(THREADTIME)
    assert record is not None
    assert record.kind == "dispatch"
    assert record.counter == 1
    assert record.pid == 15837
    assert record.tid == 15950
    assert record.version == "2.5.26"
    assert record.payload == '{"CMD":"GET_SHOP_LIST"}'
    assert record.truncated is False


def test_time_line_is_parsed_without_a_thread_id():
    """`adb logcat -v time` prints only the pid; pairing must still work."""
    record = parse_line(TIME)
    assert record is not None
    assert record.kind == "dispatch"
    assert record.pid == 16715
    assert record.tid == 0


def test_marker_line_is_parsed():
    record = parse_line(MARKER)
    assert record is not None
    assert record.kind == "marker"
    assert record.marker["fingerprint"] == "65a95d1c"
    assert record.marker["patches"] == 37
    assert record.marker["flags"] == [
        "build_marker",
        "handler_timing",
        "hit_counters",
        "log_dispatch",
    ]


def test_timing_and_response_lines():
    timing = parse_line("11-11 22:00:26.857  15837 15950 I FWTR-DEV-T-v2.5.26: 27657 us")
    assert timing is not None
    assert timing.kind == "timing"
    assert timing.micros == 27657

    response = parse_line(
        '11-11 22:00:26.900  15837 15950 I FWTR-DEV-R-v2.5.26: 1 {"result":true}'
    )
    assert response is not None
    assert response.kind == "response"
    assert response.counter == 1
    assert response.payload == '{"result":true}'


def test_unrelated_lines_are_ignored():
    for line in (
        "--------- beginning of main",
        "11-11 22:00:24.856  15837 15950 I ActivityManager: Start proc 1234:com.nexon.fwar",
        "11-11 22:00:24.856  15837 15950 I FWTR-DEV-v2.5.26: not a counter line",
        "",
    ):
        assert parse_line(line) is None


def test_truncated_payload_is_flagged():
    """`--dev-log-limit` cuts the body; the record has to say so."""
    line = (
        '11-11 22:00:24.856  15837 15950 I FWTR-DEV-v2.5.26: 7 '
        '{"CMD":"GET_MY_INFO","user_index":99'
    )
    record = parse_line(line)
    assert record is not None
    assert record.truncated is True
    payload = record.as_json()
    assert payload["truncated"] is True
    assert "json" not in payload, "a truncated body must not pretend to parse"


def test_counter_gaps_are_reported():
    capture = "\n".join(
        [
            "11-11 22:00:24.856  1 1 I FWTR-DEV-v2.5.26: 1 {\"CMD\":\"A\"}",
            "11-11 22:00:24.900  1 1 I FWTR-DEV-v2.5.26: 2 {\"CMD\":\"B\"}",
            # 3 and 4 were dropped by logd's ring buffer
            "11-11 22:00:25.000  1 1 I FWTR-DEV-v2.5.26: 5 {\"CMD\":\"C\"}",
        ]
    )
    summary = summarize(parse_capture(capture))
    assert summary.dispatches == 3
    assert summary.gaps == [(2, 5)]


def test_timing_is_attributed_to_the_preceding_request_on_the_same_thread():
    capture = "\n".join(
        [
            '11-11 22:00:24.856  1 100 I FWTR-DEV-v2.5.26: 1 {"CMD":"SLOW"}',
            '11-11 22:00:24.900  1 200 I FWTR-DEV-v2.5.26: 2 {"CMD":"FAST"}',
            "11-11 22:00:24.950  1 200 I FWTR-DEV-T-v2.5.26: 500 us",
            "11-11 22:00:25.900  1 100 I FWTR-DEV-T-v2.5.26: 9000 us",
        ]
    )
    summary = summarize(parse_capture(capture))
    assert summary.timings_by_command["FAST"] == [500]
    assert summary.timings_by_command["SLOW"] == [9000]


def test_requests_and_responses_are_paired_by_counter():
    capture = "\n".join(
        [
            '11-11 22:00:24.856  1 100 I FWTR-DEV-v2.5.26: 1 {"CMD":"A"}',
            '11-11 22:00:24.900  1 100 I FWTR-DEV-R-v2.5.26: 1 {"result":true}',
            '11-11 22:00:24.950  1 100 I FWTR-DEV-v2.5.26: 2 {"CMD":"B"}',
        ]
    )
    summary = summarize(parse_capture(capture))
    assert summary.responses == 1
    assert summary.paired == 1, "only the request with a response counts as paired"


def test_jsonl_output_round_trips(tmp_path):
    capture = tmp_path / "capture.log"
    capture.write_text("\n".join([MARKER, THREADTIME]), encoding="utf-8")
    out = tmp_path / "records.jsonl"
    assert main([str(capture), "--jsonl", str(out), "--quiet"]) == 0
    lines = [json.loads(line) for line in out.read_text().splitlines()]
    assert [line["kind"] for line in lines] == ["marker", "dispatch"]
    assert lines[1]["counter"] == 1
    assert lines[1]["json"] == {"CMD": "GET_SHOP_LIST"}


def test_empty_capture_is_an_error(tmp_path):
    capture = tmp_path / "capture.log"
    capture.write_text("nothing to see here\n", encoding="utf-8")
    assert main([str(capture), "--quiet"]) == 1


@pytest.fixture(scope="module")
def real_capture() -> str:
    from pathlib import Path

    path = Path(__file__).parent / "fixtures" / "dev_log_emulator.log"
    if not path.is_file():
        pytest.skip("no recorded device capture in tests/fixtures")
    return path.read_text(encoding="utf-8")


def test_real_capture_from_the_emulator(real_capture):
    """A capture taken from a real run must parse and pair end to end."""
    records: list[Record] = parse_capture(real_capture)
    assert records, "the fixture must contain dev lines"
    summary = summarize(records)
    assert summary.marker is not None
    assert summary.dispatches >= 3
    assert summary.timings >= 3
    assert summary.paired == 0  # the builds so far do not log responses
    assert all(count >= 1 for count in summary.commands.values())


def test_cmd_filter_keeps_only_matching_commands(tmp_path):
    capture = tmp_path / "capture.log"
    capture.write_text(
        "\n".join(
            [
                MARKER,
                '11-11 22:00:24.856  1 100 I FWTR-DEV-v2.5.26: 1 {"CMD":"GET_SHOP_LIST"}',
                '11-11 22:00:24.860  1 100 I FWTR-DEV-R-v2.5.26: 1 {"result":true}',
                "11-11 22:00:24.865  1 100 I FWTR-DEV-T-v2.5.26: 400 us",
                '11-11 22:00:25.000  1 100 I FWTR-DEV-v2.5.26: 2 {"CMD":"REQ_SELL_ITEM"}',
                '11-11 22:00:25.005  1 100 I FWTR-DEV-R-v2.5.26: 2 {"result":true}',
                "11-11 22:00:25.010  1 100 I FWTR-DEV-T-v2.5.26: 900 us",
            ]
        ),
        encoding="utf-8",
    )
    out = tmp_path / "filtered.jsonl"
    assert main([str(capture), "--cmd", "REQ_SELL_ITEM", "--jsonl", str(out), "--quiet"]) == 0
    lines = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
    assert [line["kind"] for line in lines] == ["marker", "dispatch", "response", "timing"]
    assert lines[1]["counter"] == 2
    assert lines[1]["json"] == {"CMD": "REQ_SELL_ITEM"}
