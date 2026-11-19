#!/usr/bin/env python3
"""Turns a dev-build `adb logcat` capture into analysis-ready JSONL.

The dev cave emits four kinds of line, all on their own logcat tag:

```
FWTR-DEV-v2.5.26: 1 {"CMD":"GET_SHOP_LIST","packet_no":0}     request  (+ counter)
FWTR-DEV-R-v2.5.26: 1 {"result":true,"shop_list":[...]}       response (+ counter)
FWTR-DEV-T-v2.5.26: 27657 us                                 handler time
FWTR-DEV-BUILD: FWTR-DEV v2.5.26 fp=65a95d1c n=37 flags=...   build identity
```

This tool pairs them, reports the counter gaps logd's ring buffer creates, and
prints timing statistics per command. Nothing here touches the device: give it a
file (or stdin) captured with

    adb logcat -v time -s FWTR-DEV-v2.5.26:V FWTR-DEV-R-v2.5.26:V \\
        FWTR-DEV-T-v2.5.26:V FWTR-DEV-BUILD:V > capture.log

Usage:
    python tools/dev_log_parse.py capture.log
    python tools/dev_log_parse.py capture.log --jsonl records.jsonl --md report.md
    adb logcat -d | python tools/dev_log_parse.py -
"""

from __future__ import annotations

import argparse
import json
import re
import statistics
import sys
from dataclasses import dataclass, field
from pathlib import Path

# Both logcat layouts are accepted because they carry different fields:
#
#   -v threadtime:  11-11 22:00:24.856  15837 15950 I FWTR-DEV-v2.5.26: 1 {...}
#   -v time:        11-11 22:21:41.416 I/FWTR-DEV-v2.5.26(16715): 1 {...}
#
# `-v time` has no thread id, so pairing falls back to ordering in that case.
THREADTIME_LINE = re.compile(
    r"^(?P<ts>\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)\s+"
    r"(?P<pid>\d+)\s+(?P<tid>\d+)\s+(?P<level>[VDIWEFA])\s+"
    r"(?P<tag>[^:]+?):\s?(?P<message>.*)$"
)
TIME_LINE = re.compile(
    r"^(?P<ts>\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)\s+"
    r"(?P<level>[VDIWEFA])/(?P<tag>[\w.\-]+)\s*\(\s*(?P<pid>\d+)\):\s?"
    r"(?P<message>.*)$"
)
MARKER_TAG = "FWTR-DEV-BUILD"
DISPATCH_PREFIX = "FWTR-DEV-v"
RESPONSE_PREFIX = "FWTR-DEV-R-v"
TIMING_PREFIX = "FWTR-DEV-T-v"
MARKER_BODY = re.compile(
    r"^FWTR-DEV v(?P<version>\S+) fp=(?P<fingerprint>[0-9a-f]+) "
    r"n=(?P<patches>\d+) flags=(?P<flags>\S*)$"
)
COUNTER_BODY = re.compile(r"^(?P<counter>\d+)\s(?P<payload>.*)$", re.DOTALL)
TIMING_BODY = re.compile(r"^(?P<micros>\d+)\s+us$")


@dataclass
class Record:
    """One parsed line. ``kind`` is dispatch, response, timing or marker."""

    kind: str
    ts: str
    pid: int
    tid: int
    version: str = ""
    counter: int | None = None
    payload: str = ""
    micros: int | None = None
    marker: dict[str, object] = field(default_factory=dict)
    truncated: bool = False

    def as_json(self) -> dict[str, object]:
        out: dict[str, object] = {
            "kind": self.kind,
            "ts": self.ts,
            "pid": self.pid,
            "tid": self.tid,
        }
        if self.version:
            out["version"] = self.version
        if self.counter is not None:
            out["counter"] = self.counter
        if self.kind in {"dispatch", "response"}:
            out["payload"] = self.payload
            out["truncated"] = self.truncated
            parsed = _try_json(self.payload)
            if parsed is not None:
                out["json"] = parsed
        if self.micros is not None:
            out["micros"] = self.micros
        if self.marker:
            out.update(self.marker)
        return out


def _try_json(text: str) -> object | None:
    try:
        parsed: object = json.loads(text)
    except (ValueError, TypeError):
        return None
    return parsed


def _payload_is_truncated(payload: str) -> bool:
    """A `%.*s` cut leaves the JSON unbalanced; the cave caps at --dev-log-limit."""
    if not payload.strip().startswith(("{", "[")):
        return False
    return payload.count("{") != payload.count("}") or payload.count("[") != payload.count("]")


def parse_line(line: str) -> Record | None:
    """Parses one logcat line. Anything that is not a dev line returns None."""
    stripped = line.rstrip("\n")
    match = THREADTIME_LINE.match(stripped)
    if match:
        tid = int(match.group("tid"))
    else:
        match = TIME_LINE.match(stripped)
        if not match:
            return None
        tid = 0  # `-v time` does not print the thread id
    tag = match.group("tag").strip()
    message = match.group("message")
    ts = match.group("ts")
    pid = int(match.group("pid"))

    if tag == MARKER_TAG:
        body = MARKER_BODY.match(message.strip())
        if not body:
            return None
        return Record(
            kind="marker",
            ts=ts,
            pid=pid,
            tid=tid,
            version=body.group("version"),
            marker={
                "version": body.group("version"),
                "fingerprint": body.group("fingerprint"),
                "patches": int(body.group("patches")),
                "flags": [f for f in body.group("flags").split(",") if f],
            },
        )

    if tag.startswith(RESPONSE_PREFIX):
        version = tag[len(RESPONSE_PREFIX) :]
        counter_body = COUNTER_BODY.match(message)
        if not counter_body:
            return None
        payload = counter_body.group("payload")
        return Record(
            kind="response",
            ts=ts,
            pid=pid,
            tid=tid,
            version=version,
            counter=int(counter_body.group("counter")),
            payload=payload,
            truncated=_payload_is_truncated(payload),
        )

    if tag.startswith(TIMING_PREFIX):
        version = tag[len(TIMING_PREFIX) :]
        timing = TIMING_BODY.match(message.strip())
        if not timing:
            return None
        return Record(
            kind="timing",
            ts=ts,
            pid=pid,
            tid=tid,
            version=version,
            micros=int(timing.group("micros")),
        )

    if tag.startswith(DISPATCH_PREFIX):
        version = tag[len(DISPATCH_PREFIX) :]
        counter_body = COUNTER_BODY.match(message)
        if not counter_body:
            return None
        payload = counter_body.group("payload")
        return Record(
            kind="dispatch",
            ts=ts,
            pid=pid,
            tid=tid,
            version=version,
            counter=int(counter_body.group("counter")),
            payload=payload,
            truncated=_payload_is_truncated(payload),
        )

    return None


def parse_capture(text: str) -> list[Record]:
    records: list[Record] = []
    for line in text.splitlines():
        record = parse_line(line)
        if record is not None:
            records.append(record)
    return records


@dataclass
class Summary:
    version: str
    marker: dict[str, object] | None
    dispatches: int
    responses: int
    timings: int
    truncated: int
    gaps: list[tuple[int, int]]
    paired: int
    commands: dict[str, int]
    timings_by_command: dict[str, list[int]]

    def render(self) -> str:
        lines = [f"build: {self.marker or 'no marker line in the capture'}"]
        lines.append(
            f"lines: {self.dispatches} dispatch, {self.responses} response, "
            f"{self.timings} timing"
        )
        if self.truncated:
            lines.append(
                f"truncated payloads: {self.truncated} "
                "(raise --dev-log-limit or set it to 0 to log whole bodies)"
            )
        if self.gaps:
            preview = ", ".join(f"{a}->{b}" for a, b in self.gaps[:8])
            more = "" if len(self.gaps) <= 8 else f" (+{len(self.gaps) - 8} more)"
            lines.append(f"counter gaps: {preview}{more} (logd ring dropped lines)")
        lines.append(f"request/response pairs: {self.paired}/{self.dispatches}")
        if self.commands:
            width = max(len(name) for name in self.commands)
            lines.append("")
            lines.append(f"{'command'.ljust(width)}  count   p50 ms   p95 ms    max ms")
            for name, count in sorted(self.commands.items(), key=lambda kv: -kv[1]):
                samples = self.timings_by_command.get(name, [])
                if samples:
                    ordered = sorted(samples)
                    p50 = statistics.median(ordered) / 1000
                    p95 = ordered[min(len(ordered) - 1, int(len(ordered) * 0.95))] / 1000
                    worst = ordered[-1] / 1000
                    lines.append(
                        f"{name.ljust(width)}  {count:5d}  {p50:7.1f}  {p95:7.1f}  {worst:7.1f}"
                    )
                else:
                    lines.append(f"{name.ljust(width)}  {count:5d}        -        -        -")
        return "\n".join(lines)


def summarize(records: list[Record]) -> Summary:
    marker = next((r.marker for r in records if r.kind == "marker"), None)
    version = next((r.version for r in records if r.version), "")
    dispatches = [r for r in records if r.kind == "dispatch"]
    responses = {r.counter for r in records if r.kind == "response"}

    gaps: list[tuple[int, int]] = []
    previous: int | None = None
    for record in dispatches:
        if record.counter is None:
            continue
        if previous is not None and record.counter > previous + 1:
            gaps.append((previous, record.counter))
        previous = record.counter

    commands: dict[str, int] = {}
    timings_by_command: dict[str, list[int]] = {}
    pending: list[Record] = []
    for record in records:
        if record.kind == "dispatch":
            payload = _try_json(record.payload)
            name = ""
            if isinstance(payload, dict):
                name = str(payload.get("CMD") or payload.get("cmd") or "?")
            commands[name] = commands.get(name, 0) + 1
            pending.append(record)
        elif record.kind == "timing" and pending:
            # The timing line follows its request, on the same thread when logcat
            # prints thread ids at all (`-v threadtime`).
            for index in range(len(pending) - 1, -1, -1):
                if record.tid == 0 or pending[index].tid == record.tid:
                    request = pending.pop(index)
                    payload = _try_json(request.payload)
                    name = ""
                    if isinstance(payload, dict):
                        name = str(payload.get("CMD") or payload.get("cmd") or "?")
                    if record.micros is not None:
                        timings_by_command.setdefault(name, []).append(record.micros)
                    break

    return Summary(
        version=version,
        marker=marker,
        dispatches=len(dispatches),
        responses=len(responses),
        timings=sum(1 for r in records if r.kind == "timing"),
        truncated=sum(1 for r in dispatches if r.truncated),
        gaps=gaps,
        paired=sum(1 for r in dispatches if r.counter in responses),
        commands=commands,
        timings_by_command=timings_by_command,
    )


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser for dev_log_parse."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", help="logcat capture file ('-' reads stdin)")
    parser.add_argument("--jsonl", type=Path, help="write one JSON record per line")
    parser.add_argument("--md", type=Path, help="write the summary as markdown")
    parser.add_argument("--quiet", action="store_true", help="do not print the summary")
    parser.add_argument(
        "--cmd",
        default="",
        help="comma-separated command names to filter (e.g. REQ_STAGE_VICTORY,REQ_SELL_ITEM)",
    )
    return parser


def _filter_records_by_command(records: list[Record], allowed_cmds: set[str]) -> list[Record]:
    """Filter parsed records to matching commands while preserving marker/pairing."""
    filtered: list[Record] = []
    pending: list[tuple[int, bool]] = []
    kept_counters: set[int] = set()
    for record in records:
        if record.kind == "marker":
            filtered.append(record)
        elif record.kind == "dispatch":
            payload = _try_json(record.payload)
            cmd_name = ""
            if isinstance(payload, dict):
                cmd_name = str(payload.get("CMD") or payload.get("cmd") or "")
            matched = cmd_name in allowed_cmds
            pending.append((record.tid, matched))
            if matched:
                filtered.append(record)
                if record.counter is not None:
                    kept_counters.add(record.counter)
        elif record.kind == "response":
            if record.counter is not None and record.counter in kept_counters:
                filtered.append(record)
        elif record.kind == "timing":
            matched = False
            for index in range(len(pending) - 1, -1, -1):
                if record.tid == 0 or pending[index][0] == record.tid:
                    _, matched = pending.pop(index)
                    break
            if matched:
                filtered.append(record)
    return filtered


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    raw = sys.stdin.read() if args.capture == "-" else Path(args.capture).read_text(
        encoding="utf-8", errors="replace"
    )
    records = parse_capture(raw)
    if args.cmd:
        allowed_cmds = {c.strip() for c in args.cmd.split(",") if c.strip()}
        if allowed_cmds:
            records = _filter_records_by_command(records, allowed_cmds)
    if not records:
        print(
            "no dev-build lines found. Check the capture with: adb logcat -v time "
            "-s FWTR-DEV-v2.5.26:V",
            file=sys.stderr,
        )
        return 1

    if args.jsonl:
        args.jsonl.parent.mkdir(parents=True, exist_ok=True)
        with args.jsonl.open("w", encoding="utf-8") as handle:
            for record in records:
                handle.write(json.dumps(record.as_json(), ensure_ascii=False) + "\n")

    summary = summarize(records)
    rendered = summary.render()
    if args.md:
        args.md.parent.mkdir(parents=True, exist_ok=True)
        args.md.write_text(f"```\n{rendered}\n```\n", encoding="utf-8")
    if not args.quiet:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
