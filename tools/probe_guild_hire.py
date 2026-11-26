"""Reads the guild-raid hire projection straight from the embedded server.

The payload that carries `hired_info` / `hired_equips` / `hired_runes` / `hired_soulgears`
only exists in the `REQ_START_GAME_GUILD` response, so there is no way to inspect the hire
without asking for a battle start.  That request is **not** read-only: measured on
2026-11-12 it rewrote `fwt_server_state_v1.json` (773.708 -> 774.163 bytes), so this tool
copies the state to a per-run temp path under `/data/local/tmp/` first, force-stops the app
afterwards and restores the copy (with ownership, `chmod 600`, and `restorecon`) -- with the
process dead the server has to reload the file on next launch.
The save under `/sdcard/Android/data/com.nexon.fwar` is never touched.

The body goes through the nested shells base64-encoded: passing it raw loses the JSON quotes
and the server answers `400 bad request`.

Usage, against the phone (needs root, which this build's adb has):

    python tools/probe_guild_hire.py --device <adb id> --kind member
    python tools/probe_guild_hire.py --device <adb id> --kind self

`member` sends a real guild member (the baseline the client always got); `self` sends the
player's own lord, which only produces a projection when `--guild-raid-mercenary` is in the
installed library.

Measured on 2026-11-12 (v2.5.31 + the cave):

    member : crs_idx 99000062  code 00120756  level 114  grade 6  equips 15
    self   : crs_idx 99010002  code 00120646  level 120  grade 6  equips 15   <- the shipped
             mirror row, not the player's creature 49 (code 00130816, level 74)

and in both cases `hired_costume` is null while `hired_runes`, `hired_soulgears`,
`all_soulgears` and `all_costumes` come out empty -- the four payload slots the author's stub
never fills.
"""

from __future__ import annotations

import argparse
import base64
import json
import secrets
import subprocess
import sys
from pathlib import Path

STATE = "/data/data/com.nexon.fwar/files/fwt/fwt_server_state_v1.json"
PORT = 8010

MEMBER_HIRE = {"friend_crs_idx": 99000062, "friend_idx": 9900006}


def _adb_bin() -> str:
    from core.apk_tooling import locate_tools

    return locate_tools().adb or "adb"


def _adb(device: str, command: str, timeout: int = 90) -> str:
    if device.startswith("-"):
        raise ValueError(f"invalid adb device serial: {device!r}")
    result = subprocess.run(
        [_adb_bin(), "-s", device, "shell", command],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return (result.stdout + result.stderr).replace("\r", "")


def _sha(device: str, path: str) -> str:
    return _adb(device, f"sha256sum {path} | cut -c1-24").strip()


def _build_request(cmd: str, *, lord_idx: int, **extra: object) -> str:
    body = {
        "res_type": -1,
        "lord_idx": lord_idx,
        "access_code": "local-access-code",
        "CMD": cmd,
        "packet_no": 900,
    }
    body.update(extra)
    return json.dumps(body, separators=(",", ":"))


def _post(device: str, body: str, resp_remote: str) -> bytes:
    request = (
        f"POST / HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\n"
        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n{body}"
    )
    b64 = base64.b64encode(request.encode()).decode()
    _adb(device, f"echo {b64} | base64 -d | nc 127.0.0.1 {PORT} > {resp_remote}")
    raw = subprocess.run(
        [_adb_bin(), "-s", device, "exec-out", "cat", resp_remote],
        capture_output=True,
        timeout=90,
        check=False,
    ).stdout
    return raw


def _parse_json_body(raw: bytes) -> dict:
    text = raw.decode("utf-8", "replace")
    start = text.find("{")
    if start < 0:
        raise ValueError(f"no JSON in the response: {text[:120]!r}")
    body = text[start:]
    data: dict = {}
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        data = json.loads(body[: body.rfind("}") + 1])
    return data


def _summary(payload: dict) -> str:
    info = payload.get("hired_info") or {}
    equips = payload.get("hired_equips") or []
    lines = [
        f"ERROR={payload.get('ERROR')}",
        f"hired_info   : crs_idx={info.get('crs_idx')} code={info.get('crs_code')} "
        f"level={info.get('crs_level')} grade={info.get('grade')} "
        f"potentials={len(info.get('potentials') or [])}",
        f"hired_equips : {len(equips)} items"
        + (f" | first equip_idx={equips[0].get('equip_idx')}" if equips else ""),
        f"hired_costume: {payload.get('hired_costume')}",
        f"hired_runes  : {len(payload.get('hired_runes') or [])} | "
        f"soulgears: {len(payload.get('hired_soulgears') or [])} | "
        f"all_soulgears: {len(payload.get('all_soulgears') or [])} | "
        f"all_costumes: {len(payload.get('all_costumes') or [])}",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--device", required=True, help="adb serial (root needed)")
    parser.add_argument("--kind", choices=("member", "self"), default="member")
    parser.add_argument("--lord-idx", type=int, default=993838, help="lord_idx used in probe requests")
    parser.add_argument("--combat-force", type=int, default=253289, help="combat_force sent in REQ_START_GAME_GUILD")
    parser.add_argument(
        "--attack-team",
        default="99,54,19,70,49",
        help="comma-separated creature slot indices for attack_team",
    )
    parser.add_argument("--out", default="", help="write the raw response to this file")
    args = parser.parse_args(argv)

    if not _adb(args.device, "pidof com.nexon.fwar").strip():
        print("game is not running: launch it before probing", file=sys.stderr)
        return 2

    attack_team = [int(item.strip()) for item in args.attack_team.split(",") if item.strip()]
    hire_fields = (
        MEMBER_HIRE
        if args.kind == "member"
        else {"friend_crs_idx": args.lord_idx * 10 + 2, "friend_idx": args.lord_idx}
    )
    token = secrets.token_hex(8)
    backup_remote = f"/data/local/tmp/fwt_state_{token}.bak"
    resp_remote = f"/data/local/tmp/fwt_resp_{token}.json"

    try:
        before = _sha(args.device, STATE)
        print("state before :", before)
        print(
            "backup       :",
            _adb(
                args.device,
                f"cp {STATE} {backup_remote} && sha256sum {backup_remote} | cut -c1-24",
            ).strip(),
        )

        body = _build_request(
            "REQ_START_GAME_GUILD",
            lord_idx=args.lord_idx,
            dg_code="400040",
            dg_key=0,
            combat_force=args.combat_force,
            buff_event_no=None,
            attack_team=attack_team,
            num_hero=0,
            **hire_fields,
        )
        raw = _post(args.device, body, resp_remote)
        print("response     :", len(raw), "bytes")
        if args.out:
            Path(args.out).write_bytes(raw)

        try:
            print(_summary(_parse_json_body(raw)))
        except ValueError as exc:
            print(f"invalid response: {exc}", file=sys.stderr)

        after = _sha(args.device, STATE)
        print("state after  :", after)
        if after != before:
            print("state changed -> force-stop + restore backup")
            print(
                _adb(
                    args.device,
                    f"am force-stop com.nexon.fwar; sleep 2; cp {backup_remote} {STATE}; "
                    f"chown $(stat -c %u:%g /data/data/com.nexon.fwar) {STATE}; "
                    f"chmod 600 {STATE}; restorecon {STATE} 2>/dev/null || true; "
                    f"sha256sum {STATE} | cut -c1-24",
                ).strip()
            )
        else:
            print("state intact")
    finally:
        _adb(args.device, f"rm -f {backup_remote} {resp_remote}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
